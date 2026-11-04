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

<modulesynopsis metafile="mod_http2.xml.meta">

    <name>mod_http2</name>
    <description>Soporte para la capa de transporte HTTP/2</description>
    <status>Extension</status>
    <sourcefile>mod_http2.c</sourcefile>
    <identifier>http2_module</identifier>
    <compatibility>Disponible en la versión 2.4.17 y posteriores</compatibility>

    <summary>
        <p>Este módulo proporciona soporte para HTTP/2 (<rfc>7540</rfc>)
        en el servidor HTTP Apache.</p>

        <p>Este módulo se basa en <a href="http://nghttp2.org/">libnghttp2</a>
        para proporcionar el motor principal de http/2.</p>

        <p>Debe habilitar HTTP/2 mediante <directive module="core">Protocols</directive>
        para poder usar la funcionalidad descrita en este documento. El
        protocolo HTTP/2 <a href="https://http2.github.io/faq/#does-http2-require-encryption"
        >no requiere</a> el uso de cifrado, por lo que hay dos esquemas disponibles:
        <code>h2</code> (HTTP/2 sobre TLS) y <code>h2c</code> (HTTP/2 sobre TCP).</p>

        <p>Dos esquemas de configuración útiles son:</p>

        <note><title>HTTP/2 en un contexto VirtualHost (solo TLS)</title>
        <highlight language="config">
Protocols h2 http/1.1
        </highlight>
        <p>Permite la negociación de HTTP/2 (h2) mediante ALPN sobre TLS en un
        <directive module="core" type="section">VirtualHost</directive> seguro.
        La comprobación del preámbulo de HTTP/2 (modo Direct, véase <directive module="mod_http2"
        >H2Direct</directive>) está desactivada por defecto para <code>h2</code>.</p>
        </note>

        <note><title>HTTP/2 en un contexto de servidor (TLS y texto en claro)</title>
        <highlight language="config">
Protocols h2 h2c http/1.1
        </highlight>
        <p>Permite la negociación de HTTP/2 (h2) mediante ALPN sobre TLS para
        <directive module="core" type="section">VirtualHost</directive> seguros. Permite
        la negociación de HTTP/2 en texto claro (h2c) mediante actualización (upgrade) desde
        una conexión HTTP/1.1 inicial, o mediante la comprobación del preámbulo de HTTP/2
        (modo Direct, véase <directive module="mod_http2">H2Direct</directive>).</p>
        </note>

        <p>Consulte las <a href="https://http2.github.io/faq">preguntas frecuentes (FAQ)
        oficiales de HTTP/2</a> si tiene alguna duda sobre el protocolo.</p>

    </summary>

    <section id="how-it-works"><title>Cómo funciona</title>

    <section id="dimensioning"><title>Dimensionamiento de HTTP/2</title>
        <p>
            Activar HTTP/2 en su servidor Apache repercute en el consumo de recursos,
            y si tiene un sitio con mucho tráfico, puede que necesite considerar
            cuidadosamente las implicaciones.
        </p>
        <p>
            Lo primero que se nota después de activar HTTP/2 es que los procesos de
            su servidor arrancarán hilos adicionales. La razón es que HTTP/2 entrega
            todas las peticiones que recibe a sus propios hilos <em>Worker</em>
            para su procesamiento, recoge los resultados y los envía como flujo
            al cliente.
        </p>
        <p>
            En la implementación actual, estos workers usan un grupo de hilos
            (thread pool) independiente del de los workers del MPM que quizás ya
            conozca. Así son las cosas por ahora, y no está pensado que sea así
            para siempre. (Aunque podría serlo para siempre en la línea de
            versiones 2.4.x). Por ello, los workers de HTTP/2, o H2Workers para
            abreviar, no aparecerán en <module>mod_status</module>. Tampoco se
            cuentan en directivas como <directive module="mpm_common"
            >ThreadsPerChild</directive>. Sin embargo
            toman <directive module="mpm_common">ThreadsPerChild</directive>
            como valor por defecto si no ha configurado otra cosa mediante
            <directive module="mod_http2">H2MinWorkers</directive> y
            <directive module="mod_http2">H2MaxWorkers</directive>.
        </p>
        <p>
            Otra cosa a vigilar es el consumo de memoria. Puesto que HTTP/2
            mantiene más estado en el servidor para gestionar todas las peticiones
            abiertas, sus prioridades y las dependencias entre ellas, siempre
            necesitará más memoria que el procesamiento de HTTP/1.1. Hay tres
            directivas que controlan la huella de memoria de una conexión HTTP/2:
            <directive module="mod_http2">H2MaxSessionStreams</directive>,
            <directive module="mod_http2">H2WindowSize</directive> y
            <directive module="mod_http2">H2StreamMaxMemSize</directive>.
        </p>
        <p>
            <directive module="mod_http2">H2MaxSessionStreams</directive> limita el
            número de peticiones paralelas que un cliente puede hacer en una conexión
            HTTP/2. Cuántas deba permitir depende de su sitio. El valor por defecto
            es 100, que es más que suficiente, y a menos que tenga problemas de
            memoria, yo lo mantendría así. La mayoría de las peticiones que envían
            los navegadores son GET sin cuerpo, por lo que solo consumen un poco
            de memoria hasta que empieza el procesamiento real.
        </p>
        <p>
            <directive module="mod_http2">H2WindowSize</directive> controla cuánto
            se le permite enviar al cliente como cuerpo de una petición antes de que
            tenga que esperar a que el servidor le anime a enviar más. O, visto al
            revés, es la cantidad de datos del cuerpo de la petición que el servidor
            necesita poder almacenar en búfer. Esto es por petición.
        </p>
        <p>
            Y por último, pero no menos importante, <directive module="mod_http2">H2StreamMaxMemSize</directive>
            controla cuántos datos de respuesta se almacenan en búfer. La petición
            reside en un hilo H2Worker y va produciendo datos, mientras la conexión
            HTTP/2 intenta enviarlos al cliente. Si el cliente no lee lo bastante
            rápido, la conexión almacenará en búfer esa cantidad de datos y después
            suspenderá el H2Worker.
        </p>
    </section>

    <section id="misdirected"><title>Varios hosts y peticiones mal dirigidas</title>
        <p>
            Muchos sitios usan el mismo certificado TLS para varios hosts virtuales. El
            certificado tiene un nombre comodín, como '*.example.org', o bien incluye
            varios nombres alternativos. Los navegadores que usan HTTP/2 reconocerán
            esto y reutilizarán una conexión ya abierta para esos hosts.
        </p>
        <p>
            Aunque esto es estupendo para el rendimiento, tiene un precio: esos vhosts
            necesitan más cuidado en su configuración. El problema es que tendrá
            varias peticiones para varios hosts en la misma conexión TLS. Y eso
            hace imposible la renegociación; de hecho, el estándar HTTP/2 la prohíbe.
        </p>
        <p>
            Por tanto, si tiene varios hosts virtuales que usan el mismo certificado
            y quiere usar HTTP/2 con ellos, debe asegurarse de que todos los vhosts
            tengan exactamente la misma configuración SSL. Necesita el mismo protocolo,
            los mismos cifrados y los mismos ajustes de verificación de cliente.
        </p>
        <p>
            Si mezcla las configuraciones, Apache httpd lo detectará y devolverá
            al cliente un código de respuesta especial, 421 Misdirected Request.
        </p>
    </section>

    <section id="envvars"><title>Variables de entorno</title>
        <p>
            Este módulo puede configurarse para proporcionar información relacionada
            con HTTP/2 como variables de entorno adicionales en el espacio de nombres
            de SSI y CGI, así como en configuraciones de log personalizadas
            (véase <code>%{VAR_NAME}e</code>).
        </p>

        <table border="1">
            <columnspec><column width=".3"/><column width=".2"/><column width=".5"/>
            </columnspec>
            <tr>
                <th><a name="table3">Nombre de la variable:</a></th>
                <th>Tipo de valor:</th>
                <th>Descripción:</th>
            </tr>
            <tr><td><code>HTTP2</code></td><td>flag</td><td>Se está usando HTTP/2.</td></tr>
            <tr><td><code>H2PUSH</code></td><td>flag</td><td>El Server Push de HTTP/2 está activado para esta conexión y además es compatible con el cliente.</td></tr>
            <tr><td><code>H2_PUSH</code></td><td>flag</td><td>nombre alternativo de <code>H2PUSH</code></td></tr>
            <tr><td><code>H2_PUSHED</code></td><td>string</td><td>vacío, o <code>PUSHED</code> si la petición está siendo enviada mediante PUSH por el servidor.</td></tr>
            <tr><td><code>H2_PUSHED_ON</code></td><td>number</td><td>número de flujo (stream) de HTTP/2 que originó el PUSH de esta petición.</td></tr>
            <tr><td><code>H2_STREAM_ID</code></td><td>number</td><td>número de flujo (stream) de HTTP/2 de esta petición.</td></tr>
            <tr><td><code>H2_STREAM_TAG</code></td><td>string</td><td>identificador de flujo único del proceso para HTTP/2, formado por el id de conexión y el id de flujo separados por <code>-</code>.</td></tr>
        </table>
    </section>

    </section>

    <directivesynopsis>
        <name>H2Direct</name>
        <description>Interruptor del protocolo H2 Direct</description>
        <syntax>H2Direct on|off</syntax>
        <default>H2Direct on para h2c, off para h2</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>

        <usage>
            <p>
                Esta directiva activa o desactiva el uso del modo Direct de HTTP/2. Esto
                debe usarse dentro de una sección
                <directive module="core" type="section">VirtualHost</directive>
                para activar la comunicación directa de HTTP/2 en ese host virtual.
            </p>
            <p>
                La comunicación directa significa que, si los primeros bytes que el
                servidor recibe en una conexión coinciden con el preámbulo de HTTP/2,
                se cambia inmediatamente al protocolo HTTP/2 sin más negociación.
                Este modo está definido en RFC 7540 para el caso en texto claro (h2c). Su
                uso en conexiones TLS no está exigido por el estándar.
            </p>
            <p>
                Cuando un servidor/vhost no tiene h2 ni h2c activados mediante
                <directive module="core">Protocols</directive>,
                la conexión nunca se inspecciona en busca de un preámbulo de HTTP/2.
                <directive>H2Direct</directive>
                no tiene ningún efecto en ese caso. Esto es importante para conexiones
                que usan protocolos en los que una lectura inicial podría bloquearse
                indefinidamente, como NNTP.
            </p>
            <p>
                Para los clientes que tienen conocimiento fuera de banda de que un
                servidor admite h2c, el HTTP/2 directo evita que el cliente tenga que
                realizar una actualización (upgrade) de HTTP/1.1, lo que se traduce en
                un mejor rendimiento y evita las restricciones de Upgrade sobre los
                cuerpos de las peticiones.
            </p>
            <p>
                Esto hace que el h2c directo también resulte atractivo para la
                comunicación entre servidores, cuando la conexión es de confianza o
                está protegida por otros medios.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2Direct on
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2Push</name>
        <description>Interruptor del Server Push de H2</description>
        <syntax>H2Push on|off</syntax>
        <default>H2Push on</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
            <context>directory</context>
            <context>.htaccess</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.18 y posteriores.</compatibility>

        <usage>
            <p>
                Esta directiva activa o desactiva el uso de la funcionalidad de Server
                Push del protocolo HTTP/2.
            </p>
            <p>
                El protocolo HTTP/2 permite que el servidor envíe mediante PUSH otros
                recursos a un cliente cuando este solicitó uno en particular. Esto
                resulta útil si esos recursos están relacionados de alguna forma y es
                previsible que el cliente los vaya a solicitar de todos modos. El PUSH
                ahorra entonces el tiempo que tardaría el cliente en solicitar esos
                recursos por sí mismo. Por otro lado, enviar mediante PUSH recursos que
                el cliente nunca necesita, o que ya tiene, es un desperdicio de ancho
                de banda.
            </p>
            <p>
                Los envíos mediante Server Push se detectan inspeccionando las cabeceras <code>Link</code> de
                las respuestas (véase <rfc>8288</rfc> para la
                especificación de Web Linking). Cuando un enlace especificado así tiene el atributo <code>rel=preload</code>,
                se trata como un recurso que debe enviarse mediante PUSH.
            </p>
            <p>
                Las cabeceras <code>Link</code> en las respuestas las establece la
                aplicación, o bien pueden configurarse mediante
                <directive module="mod_http2">H2PushResource</directive> o
                usando <module>mod_headers</module> de esta forma:
            </p>
            <example><title>Ejemplo con mod_headers</title>
                <highlight language="config">
&lt;Location /index.html&gt;
    Header add Link "&lt;/css/site.css&gt;;rel=preload"
    Header add Link "&lt;/images/logo.jpg&gt;;rel=preload"
&lt;/Location&gt;
                </highlight>
            </example>
            <p>
                Como muestra el ejemplo, pueden añadirse varias cabeceras link a una
                respuesta, lo que provoca que se disparen varios PUSH. El módulo no
                realiza ninguna comprobación para evitar enviar el mismo recurso dos o
                más veces al mismo cliente mediante PUSH. Úselo con cuidado.
            </p>
            <p>
                El Server Push de HTTP/2 está activado por defecto. En un servidor o
                host virtual, puede activar o desactivar esta funcionalidad para
                cualquier conexión al host. Además, puede desactivar PUSH para un
                conjunto de recursos en un Directory/Location. Esto controla qué
                recursos pueden provocar un PUSH, no qué recursos pueden enviarse
                mediante PUSH.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2Push off
                </highlight>
            </example>
            <p>
                Por último, pero no menos importante, los PUSH solo se producen cuando
                el cliente indica su disposición a aceptarlos. La mayoría de los
                navegadores lo hacen; algunos, como Safari 9,
                no. Además, los PUSH solo se producen para recursos de la misma
                <em>autoridad</em> que la de la respuesta original.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2PushDiarySize</name>
        <description>Tamaño del diario de Server Push de H2</description>
        <syntax>H2PushDiarySize <var>n</var></syntax>
        <default>H2PushDiarySize 256</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.19 y posteriores.</compatibility>

        <usage>
            <p>
                Esta directiva establece el número máximo de Server Push de HTTP/2
                que se recuerdan por conexión HTTP/2. Esto puede usarse dentro de la
                sección <directive module="core" type="section">VirtualHost</directive>
                para influir en ese número en todas las conexiones a ese host virtual.
            </p>
            <p>
                El diario de PUSH registra un resumen (digest) de los recursos
                enviados mediante PUSH (su URL) para evitar PUSH duplicados en la
                misma conexión. Estos valores no se persisten, por lo que los clientes
                que abran una nueva conexión volverán a recibir PUSH ya conocidos.
            </p>
            <p>
                Si se alcanza el tamaño máximo, las entradas más nuevas sustituyen
                a las más antiguas. Cada entrada del diario usa 8 bytes, por lo que
                un diario por defecto con 256 entradas consume alrededor de 2 KB
                de memoria.
            </p>
            <p>
                Un tamaño de 0 desactiva de forma efectiva el diario de PUSH.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2PushPriority</name>
        <description>Prioridad del Server Push de H2</description>
        <syntax>H2PushPriority <var>mime-type</var> [after|before|interleaved] [<var>weight</var>]</syntax>
        <default>H2PushPriority * After 16</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.18 y posteriores. Para que
            tenga efecto, es necesaria una versión de la librería nghttp2 1.5.0 o posterior.</compatibility>

        <usage>
            <p>
                Esta directiva define el tratamiento de la prioridad de las respuestas
                enviadas mediante PUSH en función del content-type de la respuesta.
                Normalmente se define por configuración de servidor, pero también
                puede aparecer en un host virtual.
            </p>
            <p>
                Los Server Push de HTTP/2 siempre están relacionados con una petición
                del cliente. Cada uno de esos pares petición/respuesta, o
                <em>flujos</em> (streams), tiene una dependencia
                y un peso que, juntos, definen la <em>prioridad</em> de un flujo.
            </p>
            <p>
                Cuando un flujo <em>depende</em> de otro, por ejemplo X depende de Y,
                entonces Y recibe todo el ancho de banda antes de que X reciba nada.
                Tenga en cuenta que esto no significa que Y vaya a bloquear a X. Si
                Y no tiene datos que enviar, todo el ancho de banda asignado a Y puede
                ser usado por X.
            </p>
            <p>
                Cuando un flujo tiene más de un dependiente, por ejemplo X1 y X2
                dependen ambos de Y, el <em>peso</em> determina el reparto del ancho
                de banda. Si X1 y X2 tienen el mismo peso, ambos reciben la mitad del
                ancho de banda disponible. Si el peso de X1 es el doble que el de X2,
                X1 recibe el doble de ancho de banda que X2.
            </p>
            <p>
                En última instancia, todo flujo depende del flujo <em>raíz</em>, que
                recibe todo el ancho de banda disponible, pero que nunca envía nada.
                Así que todo su ancho de banda se distribuye por peso entre sus hijos.
                Los cuales, o bien tienen datos que enviar, o distribuyen el ancho de
                banda a sus propios hijos. Y así sucesivamente. Si ninguno de los
                hijos tiene datos que enviar, ese ancho de banda se distribuye a otra
                parte según las mismas reglas.
            </p>
            <p>
                El propósito de este sistema de prioridades es aprovechar siempre el
                ancho de banda disponible, al tiempo que permite dar precedencia y
                peso a flujos concretos. Puesto que, normalmente, todos los flujos
                los inicia el cliente, es también él quien establece estas
                prioridades.
            </p>
            <p>
                Solo cuando ese flujo da lugar a un PUSH es cuando el servidor decide
                cuál es la prioridad <em>inicial</em> de ese flujo enviado mediante
                PUSH. En los ejemplos siguientes, X es el flujo del cliente. Depende
                de Y, y el servidor decide enviar mediante PUSH los flujos P1 y P2
                sobre X.
            </p>
            <p>
                La regla de prioridad por defecto es:
            </p>
            <example><title>Regla de prioridad por defecto</title>
                <highlight language="config">
H2PushPriority * After 16
                </highlight>
            </example>
            <p>
                lo que se lee como 'Enviar un flujo de PUSH de cualquier content-type
                dependiendo del flujo del cliente con un peso de 16'. Así, P1
                y P2 se enviarán después de X y, como tienen el mismo peso, se
                repartirán el ancho de banda a partes iguales entre ellos.
            </p>
            <example><title>Regla de prioridad entrelazada (Interleaved)</title>
                <highlight language="config">
H2PushPriority text/css Interleaved 256
                </highlight>
            </example>
            <p>
                lo que se lee como 'Enviar cualquier recurso CSS con la misma
                dependencia y el mismo peso que el flujo del cliente'. Si P1 tiene
                content-type 'text/css', dependerá de Y (igual que X) y su peso
                efectivo se calculará como <code>P1ew = Xw * (P1w / 256)</code>. Con
                P1w valiendo 256, esto hace que el peso efectivo sea el mismo que
                el de X. Si tanto X como P1 tienen datos que enviar, el ancho de
                banda se repartirá entre ambos a partes iguales.
            </p>
            <p>
                Con Pw especificado como 512, un flujo entrelazado enviado mediante
                PUSH recibiría el doble del peso de X. Con 128, solo la mitad. Tenga
                en cuenta que los pesos efectivos siempre están limitados a un
                máximo de 256.
            </p>
            <example><title>Regla de prioridad Before</title>
                <highlight language="config">
H2PushPriority application/json Before
                </highlight>
            </example>
            <p>
                Esto indica que cualquier flujo enviado mediante PUSH con content-type
                'application/json' debe enviarse <em>antes</em> que X. Esto hace que
                P1 dependa de Y y que X dependa de P1. Por tanto, X se estancará
                mientras P1 tenga datos que enviar. El peso efectivo se hereda del
                flujo del cliente. No está permitido especificar un peso.
            </p>
            <p>
                Tenga en cuenta que el efecto de las especificaciones de prioridad
                está limitado por los recursos disponibles del servidor. Si un
                servidor no tiene workers disponibles para los flujos enviados
                mediante PUSH, los datos de ese flujo puede que no lleguen hasta
                que otros flujos hayan terminado.
            </p>
            <p>
                Por último, pero no menos importante, hay algunas particularidades
                de la sintaxis que se usa en esta directiva:
            </p>
            <ol>
                <li>'*' es el único content-type especial que coincide con todos los
                    demás. 'image/*' no funcionará.</li>
                <li>La dependencia por defecto es 'After'. </li>
                <li>También hay pesos por defecto: para 'After' es 16, para
                    'interleaved' es 256.
                </li>
            </ol>
            <example><title>Reglas de prioridad abreviadas</title>
                <highlight language="config">
H2PushPriority application/json 32         # an After rule
H2PushPriority image/jpeg before           # weight inherited
H2PushPriority text/css   interleaved      # weight 256 default
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2Upgrade</name>
        <description>Interruptor del protocolo H2 Upgrade</description>
        <syntax>H2Upgrade on|off</syntax>
        <default>H2Upgrade on para h2c, off para h2</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
            <context>directory</context>
            <context>.htaccess</context>
        </contextlist>

        <usage>
            <p>
                Esta directiva activa o desactiva el uso del método Upgrade de
                HTTP/1.1 para cambiar a HTTP/2. Esto
                debe usarse dentro de una sección
                <directive module="core" type="section">VirtualHost</directive>
                para activar las actualizaciones (Upgrades) a HTTP/2 en ese host virtual.
            </p>
            <p>
                Este método de cambio de protocolo está definido en HTTP/1.1 y usa
                la cabecera "Upgrade" (de ahí su nombre) para anunciar la disposición
                a usar otro protocolo. Esto puede ocurrir en cualquier petición de
                una conexión HTTP/1.1.
            </p>
            <p>
                Este método de cambio de protocolo está activado por defecto en
                conexiones en texto claro (h2c potencial) y desactivado en TLS
                (h2 potencial), según exige RFC 7540.
            </p>
            <p>
                Tenga en cuenta que los Upgrade solo se aceptan para peticiones
                que no llevan cuerpo. Las peticiones POST y PUT con contenido
                nunca provocarán una actualización a HTTP/2.
                Véase <directive module="mod_http2">H2Direct</directive> para una
                alternativa a Upgrade.
            </p>
            <p>
                Este modo solo tiene efecto cuando h2 o h2c están activados mediante
                la directiva <directive module="core">Protocols</directive>.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2Upgrade on
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2MaxSessionStreams</name>
        <description>Número máximo de flujos activos por sesión HTTP/2.</description>
        <syntax>H2MaxSessionStreams <var>n</var></syntax>
        <default>H2MaxSessionStreams 100</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <usage>
            <p>
                Esta directiva establece el número máximo de flujos activos por
                sesión HTTP/2 (por ejemplo, una conexión) que permite el servidor.
                Un flujo está activo si no está <code>idle</code> ni
                <code>closed</code> según RFC 7540.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2MaxSessionStreams 20
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2StreamMaxMemSize</name>
        <description>Cantidad máxima de datos de salida almacenados en búfer por flujo.</description>
        <syntax>H2StreamMaxMemSize <var>bytes</var></syntax>
        <default>H2StreamMaxMemSize 65536</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <usage>
            <p>
                Esta directiva establece el número máximo de bytes de datos salientes
                que se almacenan en búfer en memoria para un flujo activo. Esta
                memoria no se asigna por flujo como tal. Las asignaciones se cuentan
                contra este límite en el momento en que están a punto de realizarse.
                El procesamiento del flujo se congela cuando se alcanza el límite,
                y solo continuará cuando los datos en búfer se hayan enviado al
                cliente.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2StreamMaxMemSize 128000
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2WindowSize</name>
        <description>Tamaño de la ventana de flujo para los datos ascendentes (upstream).</description>
        <syntax>H2WindowSize <var>bytes</var></syntax>
        <default>H2WindowSize 65535</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <usage>
            <p>
                Esta directiva establece el tamaño de la ventana que se usa para
                el control de flujo desde el cliente hacia el servidor y limita la
                cantidad de datos que el servidor tiene que almacenar en búfer.
                El cliente dejará de enviar en un flujo en cuanto se alcance el
                límite, hasta que el servidor anuncie más espacio disponible (al
                haber procesado parte de los datos).
            </p><p>
                Este límite solo afecta a los cuerpos de las peticiones, no a sus
                metadatos, como las cabeceras. Además, no tiene efecto sobre los
                cuerpos de las respuestas, ya que el tamaño de ventana de estos lo
                gestionan los clientes.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2WindowSize 128000
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2MinWorkers</name>
        <description>Número mínimo de hilos worker que se usan por proceso hijo.</description>
        <syntax>H2MinWorkers <var>n</var></syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Esta directiva establece el número mínimo de hilos worker que se
                deben lanzar por proceso hijo para el procesamiento de HTTP/2. Si
                no se usa esta directiva, <module>mod_http2</module> elegirá un
                valor adecuado para el módulo <code>mpm</code> cargado.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2MinWorkers 10
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2MaxWorkers</name>
        <description>Número máximo de hilos worker que se usan por proceso hijo.</description>
        <syntax>H2MaxWorkers <var>n</var></syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Esta directiva establece el número máximo de hilos worker que se
                deben lanzar por proceso hijo para el procesamiento de HTTP/2. Si
                no se usa esta directiva, <module>mod_http2</module> elegirá un
                valor adecuado para el módulo <code>mpm</code> cargado.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2MaxWorkers 20
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2MaxWorkerIdleSeconds</name>
        <description>Número máximo de segundos que los workers de h2 permanecen inactivos antes de cerrarse.</description>
        <syntax>H2MaxWorkerIdleSeconds <var>n</var></syntax>
        <default>H2MaxWorkerIdleSeconds 600</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Esta directiva establece el número máximo de segundos que un worker
                de h2 puede permanecer inactivo antes de cerrarse por sí mismo. Esto
                solo ocurre mientras el número de workers de h2 supere
                <directive module="mod_http2">H2MinWorkers</directive>.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2MaxWorkerIdleSeconds 20
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2SerializeHeaders</name>
        <description>Interruptor de serialización del procesamiento de petición/respuesta</description>
        <syntax>H2SerializeHeaders on|off</syntax>
        <default>H2SerializeHeaders off</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <usage>
            <p>
                Esta directiva activa o desactiva si las peticiones HTTP/2 deben
                serializarse en formato HTTP/1.1 para que las procese el núcleo de
                <code>httpd</code>, o si los datos binarios recibidos deben pasarse
                directamente a los <code>request_rec</code>.
            </p>
            <p>
                La serialización reduce el rendimiento, pero ofrece más
                compatibilidad retroactiva en caso de que algún filtro o hook
                personalizado la necesite.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2SerializeHeaders on
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2ModernTLSOnly</name>
        <description>Exige que las conexiones HTTP/2 sean únicamente "modern TLS"</description>
        <syntax>H2ModernTLSOnly on|off</syntax>
        <default>H2ModernTLSOnly on</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.18 y posteriores.</compatibility>

        <usage>
            <p>
                Esta directiva activa o desactiva las comprobaciones de seguridad
                en las conexiones HTTP/2 en modo TLS (https:). Esto puede usarse
                para todo el servidor o para
                <directive module="core" type="section">VirtualHost</directive> concretos.
            </p>
            <p>
                Las comprobaciones de seguridad exigen que el protocolo TLS sea al
                menos TLSv1.2 y que no se use ninguno de los cifrados listados en
                RFC 7540, Apéndice A. Estas comprobaciones se ampliarán cuando
                entren en vigor nuevos requisitos de seguridad.
            </p>
            <p>
                El nombre proviene de las definiciones de
                <a href="https://wiki.mozilla.org/Security/Server_Side_TLS">Security/Server Side TLS</a>
                de mozilla, donde se define la "modern compatibility" (compatibilidad
                moderna). Mozilla Firefox y otros navegadores exigen compatibilidad
                moderna para las conexiones HTTP/2. Como ocurre con todo en OpSec,
                esto es un objetivo cambiante y es de esperar que evolucione en
                el futuro.
            </p>
            <p>
                Uno de los propósitos de tener estas comprobaciones en
                <module>mod_http2</module> es imponer este nivel de seguridad para
                todas las conexiones, no solo las de los navegadores. El otro
                propósito es impedir la negociación de HTTP/2 como protocolo si
                no se cumplen los requisitos.
            </p>
            <p>
                En última instancia, la seguridad de la conexión TLS la determinan
                las directivas de configuración del servidor para <module>mod_ssl</module>.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2ModernTLSOnly off
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2TLSWarmUpSize</name>
        <description>Configura el número de bytes en la conexión TLS antes de hacer escrituras máximas</description>
        <syntax>H2TLSWarmUpSize <var>amount</var></syntax>
        <default>H2TLSWarmUpSize 1048576</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.18 y posteriores.</compatibility>

        <usage>
            <p>
                Esta directiva establece el número de bytes que se envían en
                registros TLS pequeños (~1300 bytes) antes de realizar escrituras
                de tamaño máximo (16k) en conexiones HTTP/2 https:.
                Esto puede usarse para todo el servidor o para
                <directive module="core" type="section">VirtualHost</directive> concretos.
            </p>
            <p>
                Las mediciones de <a href="https://www.igvita.com">google performance
                    labs</a> muestran que el mejor rendimiento en conexiones TLS se
                alcanza cuando los tamaños de registro iniciales se mantienen por
                debajo del nivel de la MTU, de forma que un registro completo quepa
                en un paquete IP.
            </p>
            <p>
                Mientras TCP ajusta su control de flujo y el tamaño de ventana,
                los registros TLS más largos pueden quedarse atascados en colas,
                o perderse y necesitar retransmisión. Esto, por supuesto, es cierto
                para todos los paquetes. Sin embargo, TLS necesita el
                registro completo para poder descifrarlo. Cualquier byte que falte
                al final bloqueará el uso de los que ya se han recibido.
            </p>
            <p>
                Una vez que se ha enviado correctamente un número suficiente de
                bytes, el estado TCP de la conexión es estable y pueden usarse
                tamaños de registro TLS máximos (16 KB) para un rendimiento óptimo.
            </p>
            <p>
                En despliegues donde los servidores solo se alcanzan de forma local
                o mediante conexiones fiables, el valor puede reducirse, y con 0
                se desactiva por completo cualquier fase de calentamiento (warmup).
            </p>
            <p>
                El siguiente ejemplo pone el tamaño a cero, lo que desactiva de
                forma efectiva cualquier fase de calentamiento.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2TLSWarmUpSize 0
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2TLSCoolDownSecs</name>
        <description>Configura el número de segundos de inactividad en TLS antes de reducir las escrituras</description>
        <syntax>H2TLSCoolDownSecs <var>seconds</var></syntax>
        <default>H2TLSCoolDownSecs 1</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.18 y posteriores.</compatibility>

        <usage>
            <p>
                Esta directiva establece el número de segundos de inactividad en
                una conexión TLS antes de que el tamaño de escritura TLS vuelva a
                una longitud pequeña (~1300 bytes).
                Esto puede usarse para todo el servidor o para
                <directive module="core" type="section">VirtualHost</directive> concretos.
            </p>
            <p>
                Véase <directive module="mod_http2">H2TLSWarmUpSize</directive> para
                una descripción del calentamiento (warmup) de TLS. <directive>H2TLSCoolDownSecs</directive>
                refleja el hecho de que las conexiones también pueden deteriorarse
                con el tiempo (y el flujo TCP se ajusta) en las conexiones inactivas.
                Resulta beneficioso para el rendimiento general volver a la fase
                previa al calentamiento después de un número de segundos sin que se
                haya enviado ningún dato.
            </p>
            <p>
                En despliegues donde las conexiones pueden considerarse fiables,
                este temporizador puede desactivarse poniéndolo a 0.
            </p>
            <p>
                El siguiente ejemplo pone los segundos a cero, lo que desactiva de
                forma efectiva cualquier enfriamiento (cool down). Las conexiones
                TLS ya calentadas permanecen con el tamaño de registro máximo.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2TLSCoolDownSecs 0
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2CopyFiles</name>
        <description>Determina la gestión de archivos en las respuestas</description>
        <syntax>H2CopyFiles on|off</syntax>
        <default>H2CopyFiles off</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
            <context>directory</context>
            <context>.htaccess</context>
        </contextlist>
        <override>FileInfo</override>
        <compatibility>Disponible en la versión 2.4.24 y posteriores.</compatibility>

        <usage>
            <p>
                Esta directiva influye en cómo se gestiona el contenido de archivo
                en las respuestas. Cuando está en <code>off</code>, que es el valor
                por defecto, los descriptores de archivo se pasan desde el
                procesamiento de la petición hasta la conexión principal, usando la
                gestión «setaside» habitual de Apache para controlar el tiempo de
                vida del archivo.
            </p>
            <p>
                Cuando está en <code>on</code>, el contenido del archivo se copia
                mientras la petición todavía se está procesando y los datos en
                búfer se pasan a la conexión principal. Esto es mejor si un módulo
                de terceros está inyectando en la respuesta archivos con tiempos
                de vida diferentes.
            </p>
            <p>
                Un ejemplo de este tipo de módulo es <code>mod_wsgi</code>, que
                puede colocar en la respuesta descriptores de archivo de Python.
                Esos archivos se cierran cuando Python considera que el procesamiento
                ha terminado, lo cual puede suceder mucho antes de que
                <module>mod_http2</module> haya acabado con ellos.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2PushResource</name>
        <description>Declara recursos para enviarlos mediante PUSH de forma temprana al cliente</description>
        <syntax>H2PushResource [add] <var>path</var> [critical]</syntax>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
            <context>directory</context>
            <context>.htaccess</context>
        </contextlist>
        <override>FileInfo</override>
        <compatibility>Disponible en la versión 2.4.24 y posteriores.</compatibility>

        <usage>
            <p>
                Cuando se añade a un directory/location, se intentarán PUSH de HTTP/2
                para todas las rutas añadidas mediante esta directiva. Esta directiva
                puede usarse varias veces para la misma location.
            </p>
            <p>
                Esta directiva envía los recursos mediante PUSH mucho antes que si se
                añaden cabeceras <code>Link</code> mediante <module>mod_headers</module>.
                <module>mod_http2</module> anuncia estos recursos en una
                respuesta provisional <code>103 Early Hints</code> al cliente.
                Esto significa que los clientes que no admiten PUSH recibirán
                igualmente indicaciones de precarga (preload) tempranas.
            </p>
            <p>
                A diferencia de establecer cabeceras de respuesta <code>Link</code>
                mediante <module>mod_headers</module>, esta directiva solo tendrá
                efecto en conexiones HTTP/2.
            </p>
            <p>
                Al añadir <code>critical</code> a un recurso de este tipo, el servidor
                le dará más preferencia en el procesamiento y enviará sus datos, en
                cuanto estén disponibles, antes que los datos de la petición principal.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2EarlyHints</name>
        <description>Determina el envío de códigos de estado 103</description>
        <syntax>H2EarlyHints on|off</syntax>
        <default>H2EarlyHints off</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.24 y posteriores.</compatibility>

        <usage>
            <p>
                Este ajuste controla si las respuestas provisionales con estado
                HTTP 103 se reenvían al cliente o no. Por defecto, actualmente
                no se reenvían, ya que varios clientes aún tienen problemas con
                respuestas provisionales inesperadas.
            </p>
            <p>
                Cuando se pone en <code>on</code>, los recursos de PUSH anunciados con
                <directive module="mod_http2">H2PushResource</directive> provocarán
                una respuesta provisional 103
                antes de la respuesta final. La respuesta 103 llevará cabeceras <code>Link</code>
                que recomiendan la precarga (<code>preload</code>) de esos recursos.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2Padding</name>
        <description>Determina el rango de bytes de relleno (padding) añadidos a los frames de payload</description>
        <syntax>H2Padding <var>numbits</var></syntax>
        <default>H2Padding 0</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.39 y posteriores.</compatibility>

        <usage>
            <p>
                Con el valor por defecto 0, no se añaden bytes de relleno a ningún
                frame de payload, p. ej. HEADERS, DATA y PUSH_PROMISE. Este es el
                comportamiento de versiones anteriores. Significa que, en ciertas
                condiciones, un observador del tráfico de red puede ver la longitud
                de esos frames en el flujo TLS.
            </p>
            <p>
                Cuando se configura un <var>numbits</var> entre 1 y 8, se añade a
                cada frame un número aleatorio en el rango [0, 2^numbits[. El valor
                aleatorio se elige de forma independiente para cada frame que el
                módulo envía de vuelta al cliente.
            </p>
            <p>
                Aunque más bytes de relleno ofrecen una mejor ofuscación de la
                longitud del mensaje, también suponen tráfico adicional. Por tanto,
                el número óptimo depende del tipo de tráfico web que curse el
                servidor.
            </p>
            <p>
                El valor por defecto de 0, es decir, sin relleno, se eligió para
                lograr la máxima compatibilidad retroactiva. Puede haber despliegues
                en los que los bytes de relleno no sean deseados o resulten
                perjudiciales. La causa más probable sería un cliente con una
                implementación defectuosa.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2OutputBuffering</name>
        <description>Determina el comportamiento de almacenamiento en búfer de la salida</description>
        <syntax>H2OutputBuffering on|off</syntax>
        <default>H2OutputBuffering on</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.48 y posteriores.</compatibility>

        <usage>
            <p>
                La directiva <directive>H2OutputBuffering</directive> controla el almacenamiento en búfer de la salida del flujo.
                El valor por defecto es <code>on</code>, que es el comportamiento de versiones anteriores. Cuando está en
                <code>off</code>, todos los bytes se ponen a disposición de la conexión principal de forma inmediata para
                enviarlos al cliente. Esto corrige problemas de interoperabilidad con ciertas variantes de gRPC.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2StreamTimeout</name>
        <description>Tiempo máximo de espera al enviar/recibir datos para el procesamiento del flujo</description>
        <syntax>H2StreamTimeout <var>time-interval</var>[s]</syntax>
        <default>Valor de <directive module="core">Timeout</directive></default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
            <context>directory</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.5.1 y posteriores.</compatibility>

        <usage>
            <p>
                <directive>H2StreamTimeout</directive> especifica el tiempo máximo
                que un flujo que se está procesando esperará a que sus datos se
                envíen o reciban.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2MaxDataFrameLen</name>
        <description>Número máximo de bytes dentro de un único frame DATA de HTTP/2</description>
        <syntax>H2MaxDataFrameLen <var>n</var></syntax>
        <default>H2MaxDataFrameLen 0</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.5.1 y posteriores.</compatibility>

        <usage>
            <p>
                <directive>H2MaxDataFrameLen</directive> limita la cantidad máxima
                de bytes del cuerpo de la respuesta que se colocan en un único
                frame DATA de HTTP/2. Si se pone a 0 no se aplica ningún límite
                (pero se respeta el tamaño máximo permitido por el protocolo).
            </p><p>
                Por defecto, el módulo intenta usar el tamaño máximo posible,
                que es de alrededor de 16 KB. Esto establece el máximo. Cuando hay
                menos datos de respuesta disponibles, se enviarán frames más
                pequeños.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2EarlyHint</name>
        <description>Añade una cabecera de respuesta que se recogerá en el 103 Early Hints</description>
        <syntax>H2EarlyHint <var>name</var> <var>value</var></syntax>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
            <context>directory</context>
            <context>.htaccess</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.5.1 y posteriores.</compatibility>

        <usage>
            <p>
                <directive>H2EarlyHint</directive> permite añadir una cabecera de
                respuesta antes de que comience el procesamiento real de la
                petición. Esas cabeceras se recogen para las respuestas intermedias
                "103 Early Hints". El propósito
                principal es enviar información de "preload" a los navegadores cliente.
            </p><p>
                <var>name</var> y <var>value</var> deben ser campos de cabecera HTTP
                válidos, o se producirán respuestas fallidas. <directive>H2EarlyHints</directive>
                debe seguir estando activada para permitir el envío de respuestas
                intermedias 103. Esta directiva puede repetirse varias veces, y los
                campos de cabecera con el mismo nombre se acumulan.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
H2EarlyHint Link "&lt;/my.css&gt;;rel=preload;as=style"
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2WebSockets</name>
        <description>Activa/desactiva WebSockets a través de HTTP/2</description>
        <syntax>H2WebSockets  on|off</syntax>
        <default>H2WebSockets off</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.5.1 y posteriores.</compatibility>

        <usage>
            <p>
                Use <directive>H2WebSockets</directive> para activar o desactivar
                el arranque (bootstrapping) de WebSockets a través del protocolo
                HTTP/2. Esta extensión del protocolo está definida en RFC 8441.
            </p><p>
                Estas peticiones llegan como un CONNECT con una cabecera
                ':protocol' adicional. El módulo transforma internamente estas
                peticiones en sus equivalentes de HTTP/1.1 antes de pasarlas al
                procesamiento interno.
            </p><p>
                Esto significa que los WebSockets de HTTP/2 pueden usarse con un
                <directive module="mod_proxy">ProxyPass</directive> con el
                parámetro 'upgrade=websocket' sin más cambios.
            </p><p>
                Para los módulos (de terceros) que gestionan WebSockets directamente
                en el servidor, el propio arranque del protocolo también funcionará.
                Sin embargo la transferencia de datos sí requiere soporte adicional
                en el caso de HTTP/2. El WebSocket negociado no podrá usar el socket
                de la conexión del cliente para el sondeo (polling) de eventos de E/S.
            </p><p>
                Puesto que activar esta funcionalidad podría romper la compatibilidad
                retroactiva para esos módulos de terceros, no está activada por defecto.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2ProxyRequests</name>
        <description>Activa/desactiva las peticiones de proxy directo a través de HTTP/2</description>
        <syntax>H2ProxyRequests  on|off</syntax>
        <default>H2ProxyRequests off</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.5.1 y posteriores.</compatibility>

        <usage>
            <p>
                Use <directive>H2ProxyRequests</directive> para activar o
                desactivar la gestión de peticiones HTTP/2 en una configuración
                de proxy directo.
            </p><p>
                De forma similar a <directive module="proxy">ProxyRequests</directive>, esta
                directiva activa el tratamiento necesario de las peticiones cuando
                HTTP/2 está activado en una configuración de proxy directo. Ambas
                directivas deben estar activadas.
            </p><p>
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>H2MaxHeaderBlockLen</name>
        <description>Tamaño máximo de las cabeceras de respuesta</description>
        <syntax>H2MaxHeaderBlockLen <var>n</var></syntax>
        <default>H2MaxHeaderBlockLen 0</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.5.1 y posteriores.</compatibility>

        <usage>
            <p>
                <directive>H2MaxHeaderBlockLen</directive> establece el límite
                sobre el tamaño total de las cabeceras de respuesta. Un valor de
                0 lo deja en el valor por defecto de 64 KB de nghttp2.
            </p>
            <p>
                Las respuestas cuyas cabeceras superen este límite (sumando todas
                las cabeceras) no se procesarán y provocarán un reset del flujo.
            </p>
        </usage>
    </directivesynopsis>

        <directivesynopsis>
        <name>H2MaxStreamErrors</name>
        <description>Cantidad máxima de errores causados por el cliente que se toleran</description>
        <syntax>H2MaxStreamErrors <var>n</var></syntax>
        <default>H2MaxStreamErrors 8</default>
        <contextlist>
            <context>server config</context>
            <context>virtual host</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.5.1 y posteriores.</compatibility>

        <usage>
            <p>
                <directive>H2MaxStreamErrors</directive> establece la cantidad
                máxima de errores de flujo de HTTP/2 causados por el cliente que
                se toleran.
                Al superar este límite, la conexión se cerrará.
                Los errores de flujo son violaciones del protocolo en un flujo
                HTTP/2 concreto que, según la especificación del protocolo, no
                requieren el cierre de la conexión, pero que pueden ser indicio
                de actividad maliciosa por parte de un cliente.
            </p>
            <p>
                Póngalo a 0 para tolerar clientes defectuosos.
            </p>
        </usage>
    </directivesynopsis>

</modulesynopsis>
