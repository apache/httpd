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

<modulesynopsis metafile="mod_lua.xml.meta">

<name>mod_lua</name>

<description>Proporciona ganchos (hooks) de Lua en diversas partes del
procesamiento de peticiones de httpd</description>
<status>Extension</status>
<sourcefile>mod_lua.c</sourcefile>
<identifier>lua_module</identifier>
<compatibility>2.3 y posteriores</compatibility>

<summary>
<p>Este módulo permite extender el servidor con scripts escritos en el
lenguaje de programación Lua. Los puntos de extensión (hooks) disponibles
con <module>mod_lua</module> incluyen muchos de los hooks disponibles para
los módulos del servidor HTTP Apache compilados de forma nativa, como la
correspondencia de peticiones con archivos, la generación de respuestas
dinámicas, el control de acceso, la autenticación y la autorización</p>

<p>Puede encontrar más información sobre el lenguaje de programación Lua en
<a href="http://www.lua.org/">el sitio web de Lua</a>.</p>

<note type="warning"><title>Advertencia</title>
<p>Este módulo otorga un gran poder sobre httpd, lo cual es a la vez una
fortaleza y un posible riesgo de seguridad. <strong>No</strong> se
recomienda usar este módulo en un servidor compartido con usuarios en los
que no confíe, ya que puede abusarse de él para alterar el funcionamiento
interno de httpd.</p>
</note>

</summary>

<section id="basicconf"><title>Configuración básica</title>

<p>La directiva básica de carga del módulo es</p>

<highlight language="config">
LoadModule lua_module modules/mod_lua.so
</highlight>

<p>
<module>mod_lua</module> proporciona un handler llamado <code>lua-script</code>,
que puede usarse con una directiva <directive
module="core">SetHandler</directive> o
<directive module="mod_mime">AddHandler</directive>:</p>

<highlight language="config">
&lt;Files "*.lua"&gt;
    SetHandler lua-script
&lt;/Files&gt;
</highlight>

<p>
Esto hará que <module>mod_lua</module> gestione las peticiones de los
archivos terminados en <code>.lua</code> invocando la función
<code>handle</code> de ese archivo.
</p>

<p>Para obtener más flexibilidad, consulte <directive>LuaMapHandler</directive>.
</p>

</section>

<section id="writinghandlers"><title>Escribir handlers</title>
<p>En la API del servidor HTTP Apache, el handler es un tipo específico de
hook responsable de generar la respuesta. Ejemplos de módulos que incluyen
un handler son <module>mod_proxy</module>, <module>mod_cgi</module>
y <module>mod_status</module>.</p>

<p><module>mod_lua</module> siempre intenta invocar una función Lua para el
handler, en lugar de simplemente evaluar el cuerpo de un script al estilo
CGI. Una función de handler se parece a lo siguiente:</p>


<highlight language="lua">
<strong>example.lua</strong><br/>
-- example handler

require "string"

--[[
     This is the default method name for Lua handlers, see the optional
     function-name in the LuaMapHandler directive to choose a different
     entry point.
--]]
function handle(r)
    r.content_type = "text/plain"

    if r.method == 'GET' then
        r:puts("Hello Lua World!\n")
        for k, v in pairs( r:parseargs() ) do
            r:puts( string.format("%s: %s\n", k, v) )
        end
    elseif r.method == 'POST' then
        r:puts("Hello Lua World!\n")
        for k, v in pairs( r:parsebody() ) do
            r:puts( string.format("%s: %s\n", k, v) )
        end
    elseif r.method == 'PUT' then
-- use our own Error contents
        r:puts("Unsupported HTTP method " .. r.method)
        r.status = 405
        return apache2.OK
    else
-- use the ErrorDocument
        return 501
    end
    return apache2.OK
end
</highlight>

<p>
Este handler simplemente imprime la uri o los argumentos codificados del
formulario en una página de texto plano.
</p>

<p>
Esto significa (y de hecho fomenta) que se pueden tener múltiples
handlers (o hooks, o filtros) en el mismo script.
</p>

</section>

<section id="writingauthzproviders">
<title>Escribir proveedores de autorización</title>

<p><module>mod_authz_core</module> proporciona una interfaz de alto nivel
para la autorización, mucho más fácil de usar que acceder directamente a
los hooks correspondientes. El primer argumento de la directiva
<directive module="mod_authz_core">Require</directive> indica el nombre
del proveedor de autorización responsable. Para cada línea
<directive module="mod_authz_core">Require</directive>,
<module>mod_authz_core</module> invocará al proveedor de autorización con
ese nombre, pasándole el resto de la línea como parámetros. El proveedor
comprobará entonces la autorización y devolverá el resultado como valor
de retorno.</p>

<p>El proveedor de autorización se invoca normalmente antes de la
autenticación. Si necesita conocer el nombre del usuario autenticado (o si
el usuario llegará a autenticarse), el proveedor debe devolver
<code>apache2.AUTHZ_DENIED_NO_USER</code>. Esto hará que la autenticación
continúe y que el proveedor de autorización se invoque una segunda vez.</p>

<p>La siguiente función de proveedor de autorización recibe dos argumentos,
una dirección ip y un nombre de usuario. Permitirá el acceso desde la
dirección ip indicada sin autenticación, o si el usuario autenticado
coincide con el segundo argumento:</p>

<highlight language="lua">
<strong>authz_provider.lua</strong><br/>

require 'apache2'

function authz_check_foo(r, ip, user)
    if r.useragent_ip == ip then
        return apache2.AUTHZ_GRANTED
    elseif r.user == nil then
        return apache2.AUTHZ_DENIED_NO_USER
    elseif r.user == user then
        return apache2.AUTHZ_GRANTED
    else
        return apache2.AUTHZ_DENIED
    end
end
</highlight>

<p>La siguiente configuración registra esta función como proveedor
<code>foo</code> y la configura para la URL <code>/</code>:</p>
<highlight language="config">
LuaAuthzProvider foo authz_provider.lua authz_check_foo
&lt;Location "/"&gt;
  Require foo 10.1.2.3 john_doe
&lt;/Location&gt;
</highlight>

</section>

<section id="writinghooks"><title>Escribir hooks</title>

<p>Las funciones de hook son el medio por el cual los módulos (y los
scripts Lua) participan en el procesamiento de las peticiones. Cada tipo
de hook expuesto por el servidor existe para un propósito específico,
como asociar peticiones con el sistema de archivos, realizar el control
de acceso o establecer los tipos mime:</p>

<table border="1" style="zebra">
    <tr>
        <th>Fase del hook</th>
        <th>Directiva de <module>mod_lua</module></th>
        <th>Descripción</th>
    </tr>
    <tr>
        <td>Quick handler</td>
        <td><directive module="mod_lua">LuaQuickHandler</directive></td>
        <td>Este es el primer hook que se invoca después de que una
            petición se haya asociado a un host o a un host virtual</td>
    </tr>
    <tr>
        <td>Pre-Translate name</td>
        <td><directive module="mod_lua">LuaHookPreTranslateName</directive></td>
        <td>Esta fase traduce la URI solicitada a un nombre de archivo en
            el sistema, antes de que ocurra la decodificación. Módulos como
            <module>mod_proxy</module> pueden operar en esta fase.</td>
    </tr>
    <tr>
        <td>Translate name</td>
        <td><directive module="mod_lua">LuaHookTranslateName</directive></td>
        <td>Esta fase traduce la URI solicitada a un nombre de archivo en
            el sistema. Módulos como <module>mod_alias</module> y
            <module>mod_rewrite</module> operan en esta fase.</td>
    </tr>
    <tr>
        <td>Map to storage</td>
        <td><directive module="mod_lua">LuaHookMapToStorage</directive></td>
        <td>Esta fase asocia los archivos con su almacenamiento físico,
            en caché o externo/proxy. Puede usarla un módulo de proxy o de
            caché</td>
    </tr>
    <tr>
        <td>Check Access</td>
        <td><directive module="mod_lua">LuaHookAccessChecker</directive></td>
        <td>Esta fase comprueba si un cliente tiene acceso a un recurso.
            Esta fase se ejecuta antes de que el usuario se autentique,
            así que tenga cuidado.
        </td>
    </tr>
    <tr>
        <td>Check User ID</td>
        <td><directive module="mod_lua">LuaHookCheckUserID</directive></td>
        <td>Esta fase se usa para comprobar el ID de usuario negociado</td>
    </tr>
    <tr>
        <td>Check Authorization</td>
        <td><directive module="mod_lua">LuaHookAuthChecker</directive> o
            <directive module="mod_lua">LuaAuthzProvider</directive></td>
        <td>Esta fase autoriza a un usuario basándose en las credenciales
            negociadas, como el ID de usuario, el certificado de cliente,
            etc.
        </td>
    </tr>
    <tr>
        <td>Check Type</td>
        <td><directive module="mod_lua">LuaHookTypeChecker</directive></td>
        <td>Esta fase comprueba el archivo solicitado y le asigna un tipo
            de contenido y un handler</td>
    </tr>
    <tr>
        <td>Fixups</td>
        <td><directive module="mod_lua">LuaHookFixups</directive></td>
        <td>Esta es la última fase de "arreglo general" antes de que se
            ejecuten los handlers de contenido. Cualquier cambio de última
            hora en la petición debe hacerse aquí.</td>
    </tr>
    <tr>
        <td>Content handler</td>
        <td>p. ej. los archivos <code>.lua</code> o mediante <directive module="mod_lua">LuaMapHandler</directive></td>
        <td>Aquí es donde se gestiona el contenido. Los archivos se leen,
            se analizan, algunos se ejecutan, y el resultado se envía al
            cliente</td>
    </tr>
    <tr>
        <td>Logging</td>
        <td><directive module="mod_lua">LuaHookLog</directive></td>
        <td>Una vez que se ha gestionado una petición, entra en varias
            fases de registro, que la anotan en el log de errores o en el
            de acceso. Mod_lua puede enlazarse al inicio de esta fase y
            controlar la salida del registro.</td>
    </tr>

</table>

<p>A las funciones de hook se les pasa el objeto de la petición como único
argumento (excepto a LuaAuthzProvider, al que también se le pasan los
argumentos de la directiva Require).
Pueden devolver cualquier valor, según el hook, pero lo más habitual es
que devuelvan OK, DONE o DECLINED, que en Lua se escriben como
<code>apache2.OK</code>, <code>apache2.DONE</code> o
<code>apache2.DECLINED</code>, o bien un código de estado HTTP.</p>


<highlight language="lua">
<strong>translate_name.lua</strong><br/>
-- example hook that rewrites the URI to a filesystem path.

require 'apache2'

function translate_name(r)
    if r.uri == "/translate-name" then
        r.filename = r.document_root .. "/find_me.txt"
        return apache2.OK
    end
    -- we don't care about this URL, give another module a chance
    return apache2.DECLINED
end
</highlight>


<highlight language="lua">
<strong>translate_name2.lua</strong><br/>
--[[ example hook that rewrites one URI to another URI. It returns a
     apache2.DECLINED to give other URL mappers a chance to work on the
     substitution, including the core translate_name hook which maps based
     on the DocumentRoot.

     Note: Use the early/late flags in the directive to make it run before
           or after mod_alias.
--]]

require 'apache2'

function translate_name(r)
    if r.uri == "/translate-name" then
        r.uri = "/find_me.txt"
        return apache2.DECLINED
    end
    return apache2.DECLINED
end
</highlight>
</section>

<section id="datastructures"><title>Estructuras de datos</title>

<dl>
<dt>request_rec</dt>
        <dd>
        <p>El request_rec se mapea como un userdata. Tiene una metatabla
        que permite hacer cosas útiles con él. En su mayor parte tiene los
        mismos campos que la estructura request_rec, muchos de los cuales
        se pueden escribir además de leer. (El contenido de los campos de
        tabla se puede cambiar, pero los campos en sí no se pueden asignar
        a tablas distintas.)</p>

        <table border="1" style="zebra">

        <tr>
          <th><strong>Nombre</strong></th>
          <th><strong>Tipo en Lua</strong></th>
          <th><strong>Escribible</strong></th>
          <th><strong>Descripción</strong></th>
        </tr>
        <tr>
          <td><code>allowoverrides</code></td>
          <td>string</td>
          <td>no</td>
          <td>Las opciones de AllowOverride aplicadas a la petición actual.</td>
        </tr>
        <tr>
          <td><code>ap_auth_type</code></td>
          <td>string</td>
          <td>sí</td>
          <td>Si se realizó una comprobación de autenticación, aquí se
          indica el tipo de autenticación (p. ej. <code>basic</code>)</td>
        </tr>
        <tr>
          <td><code>args</code></td>
          <td>string</td>
          <td>sí</td>
          <td>Los argumentos de la cadena de consulta extraídos de la
            petición (p. ej. <code>foo=bar&amp;name=johnsmith</code>)</td>
        </tr>
        <tr>
          <td><code>assbackwards</code></td>
          <td>boolean</td>
          <td>no</td>
          <td>Se establece a true si esta es una petición de estilo
            HTTP/0.9 (p. ej. <code>GET /foo</code> (sin cabeceras))</td>
        </tr>
        <tr>
          <td><code>auth_name</code></td>
          <td>string</td>
          <td>no</td>
          <td>El nombre del realm usado para la autorización (si procede).</td>
        </tr>
        <tr>
          <td><code>banner</code></td>
          <td>string</td>
          <td>no</td>
          <td>El banner del servidor, p. ej. <code>Apache HTTP Server/2.4.3 openssl/0.9.8c</code></td>
        </tr>
        <tr>
          <td><code>basic_auth_pw</code></td>
          <td>string</td>
          <td>no</td>
          <td>La contraseña de basic auth enviada con esta petición, si la hay</td>
        </tr>
        <tr>
          <td><code>canonical_filename</code></td>
          <td>string</td>
          <td>no</td>
          <td>El nombre de archivo canónico de la petición</td>
        </tr>
        <tr>
          <td><code>content_encoding</code></td>
          <td>string</td>
          <td>no</td>
          <td>La codificación de contenido de la petición actual</td>
        </tr>
        <tr>
          <td><code>content_type</code></td>
          <td>string</td>
          <td>sí</td>
          <td>El tipo de contenido de la petición actual, tal como se
            determina en la fase type_check (p. ej. <code>image/gif</code>
            o <code>text/html</code>)</td>
        </tr>
        <tr>
          <td><code>context_prefix</code></td>
          <td>string</td>
          <td>no</td>
          <td></td>
        </tr>
        <tr>
          <td><code>context_document_root</code></td>
          <td>string</td>
          <td>no</td>
          <td></td>
        </tr>

        <tr>
          <td><code>document_root</code></td>
          <td>string</td>
          <td>no</td>
          <td>La raíz de documentos del host</td>
        </tr>
        <tr>
          <td><code>err_headers_out</code></td>
          <td>table</td>
          <td>no</td>
          <td>Entorno de cabeceras MIME para la respuesta, que se imprime
            incluso en caso de error y persiste a través de redirecciones
            internas. Hay disponible una tabla de Lua de solo lectura
            adecuada para iterar como r:err_headers_out_table().</td>
        </tr>
        <tr>
          <td><code>filename</code></td>
          <td>string</td>
          <td>sí</td>
          <td>El nombre de archivo al que se asocia la petición, p. ej.
            /www/example.com/foo.txt. Se puede cambiar en las fases
            pre-translate-name, translate-name o map-to-storage de una
            petición para permitir que el handler predeterminado (o los
            handlers de script) sirvan un archivo distinto del solicitado.</td>
        </tr>
        <tr>
          <td><code>handler</code></td>
          <td>string</td>
          <td>sí</td>
          <td>El nombre del <a href="../handler.html">handler</a> que debe
            servir esta petición, p. ej. <code>lua-script</code> si debe
            servirla <module>mod_lua</module>. Normalmente se establece
            mediante las directivas <directive module="mod_mime">AddHandler</directive>
            o <directive module="core">SetHandler</directive>, pero también
            se podría establecer a través de <module>mod_lua</module> para
            permitir que otro handler sirva una petición concreta que de
            otro modo no gestionaría.
            </td>
        </tr>

        <tr>
          <td><code>headers_in</code></td>
          <td>table</td>
          <td>sí</td>
          <td>Entorno de cabeceras MIME de la petición. Contiene cabeceras
            como <code>Host, User-Agent, Referer</code>, etc. Hay
            disponible una tabla de Lua de solo lectura adecuada para
            iterar como r:headers_in_table().</td>
        </tr>
        <tr>
          <td><code>headers_out</code></td>
          <td>table</td>
          <td>sí</td>
          <td>Entorno de cabeceras MIME para la respuesta. Hay disponible
            una tabla de Lua de solo lectura adecuada para iterar como
            r:headers_out_table().</td>
        </tr>
        <tr>
          <td><code>hostname</code></td>
          <td>string</td>
          <td>no</td>
          <td>El nombre de host, tal como lo establece la cabecera
            <code>Host:</code> o una URI completa.</td>
        </tr>
        <tr>
          <td><code>is_https</code></td>
          <td>boolean</td>
          <td>no</td>
          <td>Si esta petición se realiza o no mediante HTTPS</td>
        </tr>
        <tr>
          <td><code>is_initial_req</code></td>
          <td>boolean</td>
          <td>no</td>
          <td>Si esta petición es la petición inicial o una subpetición</td>
        </tr>
        <tr>
          <td><code>limit_req_body</code></td>
          <td>number</td>
          <td>no</td>
          <td>El límite de tamaño del cuerpo de la petición para esta
            petición, o 0 si no hay límite.</td>
        </tr>
        <tr>
          <td><code>log_id</code></td>
          <td>string</td>
          <td>no</td>
          <td>El ID para identificar la petición en el log de acceso y de errores.</td>
        </tr>
        <tr>
          <td><code>method</code></td>
          <td>string</td>
          <td>no</td>
          <td>El método de la petición, p. ej. <code>GET</code> o <code>POST</code>.</td>
        </tr>
        <tr>
          <td><code>notes</code></td>
          <td>table</td>
          <td>sí</td>
          <td>Una lista de notas que se pueden pasar de un módulo a otro.
            Hay disponible una tabla de Lua de solo lectura adecuada para
            iterar como r:notes_table().</td>
        </tr>
        <tr>
          <td><code>options</code></td>
          <td>string</td>
          <td>no</td>
          <td>La directiva Options aplicada a la petición actual.</td>
        </tr>
        <tr>
          <td><code>path_info</code></td>
          <td>string</td>
          <td>no</td>
          <td>El PATH_INFO extraído de esta petición.</td>
        </tr>
        <tr>
          <td><code>port</code></td>
          <td>number</td>
          <td>no</td>
          <td>El puerto del servidor usado por la petición.</td>
        </tr>
        <tr>
          <td><code>protocol</code></td>
          <td>string</td>
          <td>no</td>
          <td>El protocolo usado, p. ej. <code>HTTP/1.1</code></td>
        </tr>
        <tr>
          <td><code>proxyreq</code></td>
          <td>string</td>
          <td>sí</td>
          <td>Indica si se trata o no de una petición de proxy. Este valor
              se establece generalmente en la fase
              post_read_request/pre_translate_name/translate_name de una
              petición.</td>
        </tr>
        <tr>
          <td><code>range</code></td>
          <td>string</td>
          <td>no</td>
          <td>El contenido de la cabecera <code>Range:</code>.</td>
        </tr>
        <tr>
          <td><code>remaining</code></td>
          <td>number</td>
          <td>no</td>
          <td>El número de bytes que quedan por leer del cuerpo de la petición.</td>
        </tr>
        <tr>
          <td><code>server_built</code></td>
          <td>string</td>
          <td>no</td>
          <td>El momento en que se compiló el ejecutable del servidor.</td>
        </tr>
        <tr>
          <td><code>server_name</code></td>
          <td>string</td>
          <td>no</td>
          <td>El nombre del servidor para esta petición.</td>
        </tr>
        <tr>
          <td><code>some_auth_required</code></td>
          <td>boolean</td>
          <td>no</td>
          <td>Si se requiere o se requirió alguna autorización para esta petición.</td>
        </tr>
        <tr>
          <td><code>subprocess_env</code></td>
          <td>table</td>
          <td>sí</td>
          <td>Las variables de entorno establecidas para esta petición. Hay
            disponible una tabla de Lua de solo lectura adecuada para
            iterar como r:subprocess_env_table().</td>
        </tr>
        <tr>
          <td><code>started</code></td>
          <td>number</td>
          <td>no</td>
          <td>El momento en que se (re)inició el servidor, en segundos
            desde el epoch (1 de enero de 1970)</td>
        </tr>
        <tr>
          <td><code>status</code></td>
          <td>number</td>
          <td>sí</td>
          <td>El código de retorno HTTP (actual) para esta petición, p. ej.
            <code>200</code> o <code>404</code>.</td>
        </tr>
        <tr>
          <td><code>the_request</code></td>
          <td>string</td>
          <td>no</td>
          <td>La cadena de la petición tal como la envió el cliente, p. ej.
            <code>GET /foo/bar HTTP/1.1</code>.</td>
        </tr>
        <tr>
          <td><code>unparsed_uri</code></td>
          <td>string</td>
          <td>no</td>
          <td>La URI sin analizar de la petición</td>
        </tr>
        <tr>
          <td><code>uri</code></td>
          <td>string</td>
          <td>sí</td>
          <td>La URI una vez que httpd la ha analizado</td>
        </tr>
        <tr>
          <td><code>user</code></td>
          <td>string</td>
          <td>sí</td>
          <td>Si se ha realizado una comprobación de autenticación, aquí se
            indica el nombre del usuario autenticado.</td>
        </tr>
        <tr>
          <td><code>useragent_ip</code></td>
          <td>string</td>
          <td>no</td>
          <td>La IP del agente de usuario que realiza la petición</td>
        </tr>
        </table>
           </dd>
    </dl>
</section>
<section id="functions"><title>Funciones integradas</title>

<p>El objeto request_rec tiene (al menos) los siguientes métodos:</p>

<highlight language="lua">
r:flush()   -- flushes the output buffer.
            -- Returns true if the flush was successful, false otherwise.

while we_have_stuff_to_send do
    r:puts("Bla bla bla\n") -- print something to client
    r:flush() -- flush the buffer (send to client)
    r.usleep(500000) -- fake processing time for 0.5 sec. and repeat
end
</highlight>

<highlight language="lua">
r:add_output_filter(filter_name) -- add an output filter:

r:add_output_filter("fooFilter") -- add the fooFilter to the output stream
</highlight>

<highlight language="lua">
r:sendfile(filename) -- sends an entire file to the client, using sendfile if supported by the current platform:

if use_sendfile_thing then
    r:sendfile("/var/www/large_file.img")
end
</highlight>

<highlight language="lua">
r:parseargs() -- returns two tables; one standard key/value table for regular GET data,
              -- and one for multi-value data (fx. foo=1&amp;foo=2&amp;foo=3):

local GET, GETMULTI = r:parseargs()
r:puts("Your name is: " .. GET['name'] or "Unknown")
</highlight>

<highlight language="lua">
r:parsebody([sizeLimit]) -- parse the request body as a POST and return two lua tables,
                         -- just like r:parseargs().
                         -- An optional number may be passed to specify the maximum number
                         -- of bytes to parse. Default is 8192 bytes:

local POST, POSTMULTI = r:parsebody(1024*1024)
r:puts("Your name is: " .. POST['name'] or "Unknown")
</highlight>

<highlight language="lua">
r:puts("hello", " world", "!") -- print to response body, self explanatory
</highlight>

<highlight language="lua">
r:write("a single string") -- print to response body, self explanatory
</highlight>

<highlight language="lua">
r:escape_html("&lt;html&gt;test&lt;/html&gt;") -- Escapes HTML code and returns the escaped result
</highlight>

<highlight language="lua">
r:base64_encode(string) -- Encodes a string using the Base64 encoding standard:

local encoded = r:base64_encode("This is a test") -- returns VGhpcyBpcyBhIHRlc3Q=
</highlight>

<highlight language="lua">
r:base64_decode(string) -- Decodes a Base64-encoded string:

local decoded = r:base64_decode("VGhpcyBpcyBhIHRlc3Q=") -- returns 'This is a test'
</highlight>

<highlight language="lua">
r:md5(string) -- Calculates and returns the MD5 digest of a string (binary safe):

local hash = r:md5("This is a test") -- returns ce114e4501d2f4e2dcea3e17b546f339
</highlight>

<highlight language="lua">
r:sha1(string) -- Calculates and returns the SHA1 digest of a string (binary safe):

local hash = r:sha1("This is a test") -- returns a54d88e06612d820bc3be72877c74f257b561b19
</highlight>

<highlight language="lua">
r:escape(string) -- URL-Escapes a string:

local url = "http://foo.bar/1 2 3 &amp; 4 + 5"
local escaped = r:escape(url) -- returns 'http%3a%2f%2ffoo.bar%2f1+2+3+%26+4+%2b+5'
</highlight>

<highlight language="lua">
r:unescape(string) -- Unescapes an URL-escaped string:

local url = "http%3a%2f%2ffoo.bar%2f1+2+3+%26+4+%2b+5"
local unescaped = r:unescape(url) -- returns 'http://foo.bar/1 2 3 &amp; 4 + 5'
</highlight>

<highlight language="lua">
r:construct_url(string) -- Constructs an URL from an URI

local url = r:construct_url(r.uri)
</highlight>

<highlight language="lua">
r.mpm_query(number) -- Queries the server for MPM information using ap_mpm_query:

local mpm = r.mpm_query(14)
if mpm == 1 then
    r:puts("This server uses the Event MPM")
end
</highlight>

<highlight language="lua">
r:expr(string) -- Evaluates an <a href="../expr.html">expr</a> string.

if r:expr("%{HTTP_HOST} =~ /^www/") then
    r:puts("This host name starts with www")
end
</highlight>

<highlight language="lua">
r:scoreboard_process(a) -- Queries the server for information about the process at position <code>a</code>:

local process = r:scoreboard_process(1)
r:puts("Server 1 has PID " .. process.pid)
</highlight>

<highlight language="lua">
r:scoreboard_worker(a, b) -- Queries for information about the worker thread, <code>b</code>, in process <code>a</code>:

local thread = r:scoreboard_worker(1, 1)
r:puts("Server 1's thread 1 has thread ID " .. thread.tid .. " and is in " .. thread.status .. " status")
</highlight>


<highlight language="lua">
r:clock() -- Returns the current time with microsecond precision
</highlight>

<highlight language="lua">
r:requestbody(filename) -- Reads and returns the request body of a request.
                -- If 'filename' is specified, it instead saves the
                -- contents to that file:

local input = r:requestbody()
r:puts("You sent the following request body to me:\n")
r:puts(input)
</highlight>

<highlight language="lua">
r:add_input_filter(filter_name) -- Adds 'filter_name' as an input filter
</highlight>

<highlight language="lua">
r.module_info(module_name) -- Queries the server for information about a module

local mod = r.module_info("mod_lua.c")
if mod then
    for k, v in pairs(mod.commands) do
       r:puts( ("%s: %s\n"):format(k,v)) -- print out all directives accepted by this module
    end
end
</highlight>

<highlight language="lua">
r:loaded_modules() -- Returns a list of modules loaded by httpd:

for k, module in pairs(r:loaded_modules()) do
    r:puts("I have loaded module " .. module .. "\n")
end
</highlight>

<highlight language="lua">
r:runtime_dir_relative(filename) -- Compute the name of a run-time file (e.g., shared memory "file")
                         -- relative to the appropriate run-time directory.
</highlight>

<highlight language="lua">
r:server_info() -- Returns a table containing server information, such as
                -- the name of the httpd executable file, mpm used etc.
</highlight>

<highlight language="lua">
r:set_document_root(file_path) -- Sets the document root for the request to file_path
</highlight>

<!--
<highlight language="lua">
r:add_version_component(component_string) - - Adds a component to the server banner.
</highlight>
-->

<highlight language="lua">
r:set_context_info(prefix, docroot) -- Sets the context prefix and context document root for a request
</highlight>

<highlight language="lua">
r:os_escape_path(file_path) -- Converts an OS path to a URL in an OS dependent way
</highlight>

<highlight language="lua">
r:escape_logitem(string) -- Escapes a string for logging
</highlight>

<highlight language="lua">
r.strcmp_match(string, pattern) -- Checks if 'string' matches 'pattern' using strcmp_match (globs).
                        -- fx. whether 'www.example.com' matches '*.example.com':

local match = r.strcmp_match("foobar.com", "foo*.com")
if match then
    r:puts("foobar.com matches foo*.com")
end
</highlight>

<highlight language="lua">
r:set_keepalive() -- Sets the keepalive status for a request. Returns true if possible, false otherwise.
</highlight>

<highlight language="lua">
r:make_etag() -- Constructs and returns the etag for the current request.
</highlight>

<highlight language="lua">
r:send_interim_response(clear) -- Sends an interim (1xx) response to the client.
                       -- if 'clear' is true, available headers will be sent and cleared.
</highlight>

<highlight language="lua">
r:custom_response(status_code, string) -- Construct and set a custom response for a given status code.
                               -- This works much like the ErrorDocument directive:

r:custom_response(404, "Baleted!")
</highlight>

<highlight language="lua">
r.exists_config_define(string) -- Checks whether a configuration definition exists or not:

if r.exists_config_define("FOO") then
    r:puts("httpd was probably run with -DFOO, or it was defined in the configuration")
end
</highlight>

<highlight language="lua">
r:state_query(string) -- Queries the server for state information
</highlight>

<highlight language="lua">
r:stat(filename [,wanted]) -- Runs stat() on a file, and returns a table with file information:

local info = r:stat("/var/www/foo.txt")
if info then
    r:puts("This file exists and was last modified at: " .. info.modified)
end
</highlight>

<highlight language="lua">
r:regex(string, pattern [,flags]) -- Runs a regular expression match on a string, returning captures if matched:

local matches = r:regex("foo bar baz", [[foo (\w+) (\S*)]])
if matches then
    r:puts("The regex matched, and the last word captured ($2) was: " .. matches[2])
end

-- Example ignoring case sensitivity:
local matches = r:regex("FOO bar BAz", [[(foo) bar]], 1)

-- Flags can be a bitwise combination of:
-- 0x01: Ignore case
-- 0x02: Multiline search
</highlight>

<highlight language="lua">
r.usleep(number_of_microseconds) -- Puts the script to sleep for a given number of microseconds.
</highlight>

<highlight language="lua">
r:dbacquire(dbType[, dbParams]) -- Acquires a connection to a database and returns a database class.
                        -- See '<a href="#databases">Database connectivity</a>' for details.
</highlight>

<highlight language="lua">
r:ivm_set("key", value) -- Set an Inter-VM variable to hold a specific value.
                        -- These values persist even though the VM is gone or not being used,
                        -- and so should only be used if MaxConnectionsPerChild is > 0
                        -- Values can be numbers, strings and booleans, and are stored on a
                        -- per process basis (so they won't do much good with a prefork mpm)

r:ivm_get("key")        -- Fetches a variable set by ivm_set. Returns the contents of the variable
                        -- if it exists or nil if no such variable exists.

-- An example getter/setter that saves a global variable outside the VM:
function handle(r)
    -- First VM to call this will get no value, and will have to create it
    local foo = r:ivm_get("cached_data")
    if not foo then
        foo = do_some_calcs() -- fake some return value
        r:ivm_set("cached_data", foo) -- set it globally
    end
    r:puts("Cached data is: ", foo)
end
</highlight>

<highlight language="lua">
r:htpassword(string [,algorithm [,cost]]) -- Creates a password hash from a string.
                                          -- algorithm: 0 = APMD5 (default), 1 = SHA, 2 = BCRYPT, 3 = CRYPT.
                                          -- cost: only valid with BCRYPT algorithm (default = 5).
</highlight>

<highlight language="lua">
r:mkdir(dir [,mode]) -- Creates a directory and sets mode to optional mode parameter.
</highlight>

<highlight language="lua">
r:mkrdir(dir [,mode]) -- Creates directories recursive and sets mode to optional mode parameter.
</highlight>

<highlight language="lua">
r:rmdir(dir) -- Removes a directory.
</highlight>

<highlight language="lua">
r:touch(file [,mtime]) -- Sets the file modification time to current time or to optional mtime msec value.
</highlight>

<highlight language="lua">
r:get_direntries(dir) -- Returns a table with all directory entries.

function handle(r)
  local dir = r.context_document_root
  for _, f in ipairs(r:get_direntries(dir)) do
    local info = r:stat(dir .. "/" .. f)
    if info then
      local mtime = os.date(fmt, info.mtime / 1000000)
      local ftype = (info.filetype == 2) and "[dir] " or "[file]"
      r:puts( ("%s %s %10i %s\n"):format(ftype, mtime, info.size, f) )
    end
  end
end
</highlight>

<highlight language="lua">
r.date_parse_rfc(string) -- Parses a date/time string and returns seconds since epoche.
</highlight>

<highlight language="lua">
r:getcookie(key) -- Gets a HTTP cookie
</highlight>

<highlight language="lua">
r:setcookie{
  key = [key],
  value = [value],
  expires = [expiry],
  secure = [boolean],
  httponly = [boolean],
  path = [path],
  domain = [domain]
} -- Sets a HTTP cookie, for instance:

r:setcookie{
  key = "cookie1",
  value = "HDHfa9eyffh396rt",
  expires = os.time() + 86400,
  secure = true
}
</highlight>

<highlight language="lua">
r:wsupgrade() -- Upgrades a connection to WebSockets if possible (and requested):
if r:wsupgrade() then -- if we can upgrade:
    r:wswrite("Welcome to websockets!") -- write something to the client
    r:wsclose()  -- goodbye!
end
</highlight>

<highlight language="lua">
r:wsread() -- Reads a WebSocket frame from a WebSocket upgraded connection (see above):

local line, isFinal = r:wsread() -- isFinal denotes whether this is the final frame.
                                 -- If it isn't, then more frames can be read
r:wswrite("You wrote: " .. line)
</highlight>

<highlight language="lua">
r:wswrite(line) -- Writes a frame to a WebSocket client:
r:wswrite("Hello, world!")
</highlight>

<highlight language="lua">
r:wsclose() -- Closes a WebSocket request and terminates it for httpd:

if r:wsupgrade() then
    r:wswrite("Write something: ")
    local line = r:wsread() or "nothing"
    r:wswrite("You wrote: " .. line);
    r:wswrite("Goodbye!")
    r:wsclose()
end
</highlight>


</section>

<section id="logging"><title>Funciones de registro</title>

<highlight language="lua">
-- examples of logging messages
r:trace1("This is a trace log message") -- trace1 through trace8 can be used
r:debug("This is a debug log message")
r:info("This is an info log message")
r:notice("This is a notice log message")
r:warn("This is a warn log message")
r:err("This is an err log message")
r:alert("This is an alert log message")
r:crit("This is a crit log message")
r:emerg("This is an emerg log message")
</highlight>

</section>

<section id="apache2"><title>El paquete apache2</title>
<p>Hay disponible un paquete llamado <code>apache2</code> con (al menos) el
siguiente contenido.</p>
<dl>
  <dt>apache2.OK</dt>
  <dd>constante interna OK. Los handlers deben devolverla si han
  gestionado la petición.</dd>
  <dt>apache2.DECLINED</dt>
  <dd>constante interna DECLINED. Los handlers deben devolverla si
  no van a gestionar la petición.</dd>
  <dt>apache2.DONE</dt>
  <dd>constante interna DONE.</dd>
  <dt>apache2.version</dt>
  <dd>Cadena de versión del servidor HTTP Apache</dd>
  <dt>apache2.HTTP_MOVED_TEMPORARILY</dt>
  <dd>código de estado HTTP</dd>
  <dt>apache2.PROXYREQ_NONE, apache2.PROXYREQ_PROXY, apache2.PROXYREQ_REVERSE, apache2.PROXYREQ_RESPONSE</dt>
  <dd>constantes internas usadas por <module>mod_proxy</module></dd>
  <dt>apache2.AUTHZ_DENIED, apache2.AUTHZ_GRANTED, apache2.AUTHZ_NEUTRAL, apache2.AUTHZ_GENERAL_ERROR, apache2.AUTHZ_DENIED_NO_USER</dt>
  <dd>constantes internas usadas por <module>mod_authz_core</module></dd>

</dl>
<p>(El resto de los códigos de estado HTTP aún no están implementados.)</p>
</section>

<section id="modifying_buckets">
    <title>Modificar contenidos con filtros Lua</title>
    <p>
    Las funciones de filtro implementadas mediante <directive module="mod_lua">LuaInputFilter</directive>
    o <directive module="mod_lua">LuaOutputFilter</directive> se diseñan como
    funciones no bloqueantes de tres etapas que usan coroutines para
    suspender y reanudar una función a medida que se envían buckets por la
    cadena de filtros. La estructura básica de una función de este tipo es:
    </p>
    <highlight language="lua">
function filter(r)
    -- Our first yield is to signal that we are ready to receive buckets.
    -- Before this yield, we can set up our environment, check for conditions,
    -- and, if we deem it necessary, decline filtering a request altogether:
    if something_bad then
        return -- This would skip this filter.
    end
    -- Regardless of whether we have data to prepend, a yield MUST be called here.
    -- Note that only output filters can prepend data. Input filters must use the
    -- final stage to append data to the content.
    coroutine.yield([optional header to be prepended to the content])

    -- After we have yielded, buckets will be sent to us, one by one, and we can
    -- do whatever we want with them and then pass on the result.
    -- Buckets are stored in the global variable 'bucket', so we create a loop
    -- that checks if 'bucket' is not nil:
    while bucket ~= nil do
        local output = mangle(bucket) -- Do some stuff to the content
        coroutine.yield(output) -- Return our new content to the filter chain
    end

    -- Once the buckets are gone, 'bucket' is set to nil, which will exit the
    -- loop and land us here. Anything extra we want to append to the content
    -- can be done by doing a final yield here. Both input and output filters
    -- can append data to the content in this phase.
    coroutine.yield([optional footer to be appended to the content])
end
    </highlight>
</section>

<section id="databases">
    <title>Conectividad con bases de datos</title>
    <p>
    Mod_lua implementa una funcionalidad sencilla de base de datos para
    consultar y ejecutar comandos en los motores de bases de datos más
    populares (MySQL, PostgreSQL, FreeTDS, ODBC, SQLite, Oracle), así como
    con mod_dbd.</p>
    <p>
    El <code>dbType</code> que se usa como primer parámetro de
    <code>dbacquire</code> distingue entre mayúsculas y minúsculas.</p>
    <p>
    Debe ser uno de <code>mysql</code>, <code>pgsql</code>, <code>freetds</code>,
    <code>odbc</code>, <code>sqlite2</code>, <code>sqlite3</code>, <code>oracle</code>
    o <code>mod_dbd</code>.
    </p>
    <p>El siguiente ejemplo muestra cómo adquirir un identificador de base
    de datos y devolver información de una tabla:</p>
    <highlight language="lua">
function handle(r)
    -- Acquire a database handle
    local database, err = r:dbacquire("mysql", "server=localhost,user=someuser,pass=somepass,dbname=mydb")
    if not err then
        -- Select some information from it
        local results, err = database:select(r, "SELECT `name`, `age` FROM `people` WHERE 1")
        if not err then
            local rows = results(0) -- fetch all rows synchronously
            for k, row in pairs(rows) do
                r:puts( string.format("Name: %s, Age: %s&lt;br/&gt;", row[1], row[2]) )
            end
        else
            r:puts("Database query error: " .. err)
        end
        database:close()
    else
        r:puts("Could not connect to the database: " .. err)
    end
end
    </highlight>
    <p>
    Para utilizar <module>mod_dbd</module>, especifique <code>mod_dbd</code>
    como tipo de base de datos, o deje el campo en blanco:
    </p>
    <highlight language="lua">
    local database = r:dbacquire("mod_dbd")
    </highlight>
    <section id="database_object">
        <title>El objeto de base de datos y sus funciones</title>
        <p>El objeto de base de datos devuelto por <code>dbacquire</code>
        tiene los siguientes métodos:</p>
        <p><strong>Select y query normales sobre una base de datos:</strong></p>
    <highlight language="lua">
-- Run a statement and return the number of rows affected:
local affected, errmsg = database:query(r, "DELETE FROM `tbl` WHERE 1")

-- Run a statement and return a result set that can be used synchronously or async:
local result, errmsg = database:select(r, "SELECT * FROM `people` WHERE 1")
    </highlight>
        <p><strong>Usar statements preparados (recomendado):</strong></p>
    <highlight language="lua">
-- Create and run a prepared statement:
local statement, errmsg = database:prepare(r, "DELETE FROM `tbl` WHERE `age` > %u")
if not errmsg then
    local result, errmsg = statement:query(20) -- run the statement with age &gt; 20
end

-- Fetch a prepared statement from a DBDPrepareSQL directive:
local statement, errmsg = database:prepared(r, "someTag")
if not errmsg then
    local result, errmsg = statement:select("John Doe", 123) -- inject the values "John Doe" and 123 into the statement
end

</highlight>
        <p><strong>Escapar valores, cerrar bases de datos, etc.:</strong></p>
    <highlight language="lua">
-- Escape a value for use in a statement:
local escaped = database:escape(r, [["'|blabla]])

-- Close a database connection and free up handles:
database:close()

-- Check whether a database connection is up and running:
local connected = database:active()
    </highlight>
    </section>
    <section id="result_sets">
    <title>Trabajar con conjuntos de resultados</title>
    <p>El conjunto de resultados devuelto por <code>db:select</code> o por
    las funciones de statement preparado creadas mediante
    <code>db:prepare</code> se puede usar para obtener filas de forma
    sincrónica o asincrónica, según el número de fila indicado:<br/>
    <code>result(0)</code> obtiene todas las filas de forma sincrónica,
    devolviendo una tabla de filas.<br/>
    <code>result(-1)</code> obtiene la siguiente fila disponible del
    conjunto, de forma asincrónica.<br/>
    <code>result(N)</code> obtiene la fila número <code>N</code>, de forma
    asincrónica:
    </p>
    <highlight language="lua">
-- fetch a result set using a regular query:
local result, err = db:select(r, "SELECT * FROM `tbl` WHERE 1")

local rows = result(0) -- Fetch ALL rows synchronously
local row = result(-1) -- Fetch the next available row, asynchronously
local row = result(1234) -- Fetch row number 1234, asynchronously
local row = result(-1, true) -- Fetch the next available row, using row names as key indexes.
    </highlight>
    <p>Se puede construir una función que devuelva una función iterativa
    para recorrer todas las filas de forma sincrónica o asincrónica, según
    el argumento async:
    </p>
    <highlight language="lua">
function rows(resultset, async)
    local a = 0
    local function getnext()
        a = a + 1
        local row = resultset(-1)
        return row and a or nil, row
    end
    if not async then
        return pairs(resultset(0))
    else
        return getnext, self
    end
end

local statement, err = db:prepare(r, "SELECT * FROM `tbl` WHERE `age` > %u")
if not err then
     -- fetch rows asynchronously:
    local result, err = statement:select(20)
    if not err then
        for index, row in rows(result, true) do
            ....
        end
    end

     -- fetch rows synchronously:
    local result, err = statement:select(20)
    if not err then
        for index, row in rows(result, false) do
            ....
        end
    end
end
    </highlight>
    </section>
    <section id="closing_databases">
        <title>Cerrar una conexión de base de datos</title>

    <p>Los identificadores de base de datos deben cerrarse con
    <code>database:close()</code> cuando ya no se necesiten. Si no los
    cierra manualmente, con el tiempo el recolector de basura los cerrará
    a través de <module>mod_lua</module>, pero puede acabar teniendo
    demasiadas conexiones sin usar a la base de datos si deja el cierre en
    manos de <module>mod_lua</module>. En esencia, las dos medidas
    siguientes son equivalentes:
    </p>
    <highlight language="lua">
-- Method 1: Manually close a handle
local database = r:dbacquire("mod_dbd")
database:close() -- All done

-- Method 2: Letting the garbage collector close it
local database = r:dbacquire("mod_dbd")
database = nil -- throw away the reference
collectgarbage() -- close the handle via GC
</highlight>
    </section>
    <section id="database_caveat">
    <title>Precauciones al trabajar con bases de datos</title>
    <p>Aunque las funciones estándar <code>query</code> y <code>run</code>
    están disponibles libremente, se recomienda usar statements preparados
    siempre que sea posible, tanto para optimizar el rendimiento (si su
    identificador de base de datos se mantiene abierto durante mucho
    tiempo) como para minimizar el riesgo de ataques de inyección SQL.
    <code>run</code> y <code>query</code> solo deben usarse cuando no se
    insertan variables en un statement (un statement estático). Cuando use
    statements dinámicos, use <code>db:prepare</code> o <code>db:prepared</code>.
    </p>
    </section>

</section>

<directivesynopsis>
<name>LuaRoot</name>
<description>Especifica la ruta base para resolver rutas relativas en las directivas de <module>mod_lua</module></description>
<syntax>LuaRoot /path/to/a/directory</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>Especifica la ruta base que se usará para evaluar todas las rutas
    relativas dentro de <module>mod_lua</module>. Si no se especifica, se
    resolverán en relación con el directorio de trabajo actual, lo cual no
    siempre funciona bien en un servidor.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaScope</name>
<description>Uno de once, request, conn, thread -- el valor predeterminado es once</description>
<syntax>LuaScope once|request|conn|thread|server [min] [max]</syntax>
<default>LuaScope once</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>Especifica el ámbito del ciclo de vida del intérprete de Lua que
    usarán los handlers en este "Directory". El valor predeterminado es
    "once"</p>

   <dl>
    <dt>once:</dt> <dd>usa el intérprete una vez y lo descarta.</dd>

    <dt>request:</dt> <dd>usa el intérprete para gestionar cualquier cosa
             basada en el mismo archivo dentro de esta petición, que
             también tiene ámbito de petición.</dd>

    <dt>conn:</dt> <dd>Igual que request, pero asociado al connection_rec</dd>

    <dt>thread:</dt> <dd>Usa el intérprete durante la vida del hilo que
            gestiona la petición (solo disponible con MPM con hilos).</dd>

    <dt>server:</dt>  <dd>Este caso es distinto de los demás porque el
            ámbito de servidor tiene una vida bastante larga, y varios
            hilos compartirán el mismo server_rec. Para adaptarse a esto,
            los estados de Lua con ámbito de servidor se guardan en una
            lista de recursos de apr. Los argumentos <code>min</code> y
            <code>max</code> especifican el número mínimo y máximo de
            estados de Lua que se mantienen en el pool.</dd>
   </dl>
    <p>
    En general, los ámbitos <code>thread</code> y <code>server</code> se
    ejecutan aproximadamente de 2 a 3 veces más rápido que el resto, porque
    no tienen que crear nuevos estados de Lua en cada petición (sobre todo
    con el MPM event, ya que incluso las peticiones keepalive usarán un
    hilo nuevo en cada petición). Si está seguro de que sus scripts no
    tendrán problemas al reutilizar un estado, entonces debería usar los
    ámbitos <code>thread</code> o <code>server</code> para obtener el
    máximo rendimiento. Aunque el ámbito <code>thread</code> ofrecerá las
    respuestas más rápidas, el ámbito <code>server</code> usará menos
    memoria, ya que los estados se agrupan en un pool, lo que permite, por
    ejemplo, que 1000 hilos compartan solo 100 estados de Lua, usando así
    solo el 10% de la memoria que requeriría el ámbito <code>thread</code>.
    </p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaMapHandler</name>
<description>Asocia una ruta a un handler de lua</description>
<syntax>LuaMapHandler uri-pattern /path/to/lua/script.lua [function-name]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<usage>
    <p>Esta directiva hace corresponder un patrón de uri con la invocación
    de una función de handler específica en un archivo específico. Usa
    expresiones regulares PCRE para comparar la uri, y admite interpolar
    los grupos coincidentes tanto en la ruta de archivo como en el nombre
    de la función. Tenga cuidado al escribir sus expresiones regulares
    para evitar problemas de seguridad.</p>
   <example><title>Ejemplos:</title>
   <highlight language="config">
    LuaMapHandler "/(\w+)/(\w+)" "/scripts/$1.lua" "handle_$2"
    </highlight>
   </example>
        <p>Esto haría que uris como /photos/show?id=9 se asociaran al
        archivo /scripts/photos.lua e invocaran a la función de handler
        handle_show en la vm de lua después de cargar ese archivo.</p>

<highlight language="config">
    LuaMapHandler "/bingo" "/scripts/wombat.lua"
</highlight>
        <p>Esto invocaría la función "handle", que es la predeterminada
        si no se proporciona un nombre de función específico.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaPackagePath</name>
<description>Añade un directorio al package.path de lua</description>
<syntax>LuaPackagePath /path/to/include/?.lua</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
    <usage><p>Añade una ruta a la ruta de búsqueda de módulos de lua. Sigue
    las mismas convenciones que lua. Esto simplemente modifica el
    package.path en las vm de lua.</p>

    <example><title>Ejemplos:</title>
    <highlight language="config">
LuaPackagePath "/scripts/lib/?.lua"
LuaPackagePath "/scripts/lib/?/init.lua"
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaPackageCPath</name>
<description>Añade un directorio al package.cpath de lua</description>
<syntax>LuaPackageCPath /path/to/include/?.soa</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage>
    <p>Añade una ruta a la ruta de búsqueda de bibliotecas compartidas de
    lua. Sigue las mismas convenciones que lua. Esto simplemente modifica
    el package.cpath en las vm de lua.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaCodeCache</name>
<description>Configura la caché de código compilado.</description>
<syntax>LuaCodeCache stat|forever|never</syntax>
<default>LuaCodeCache stat</default>
<contextlist>
<context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>

<usage><p>
    Especifica el comportamiento de la caché de código en memoria. El
    valor predeterminado es stat, que hace un stat del script de nivel
    superior (no de los que se incluyan) cada vez que se necesita ese
    archivo, y lo recarga si la hora de modificación indica que es más
    reciente que el que ya ha cargado. Los demás valores hacen que
    mantenga el archivo en caché para siempre (sin hacer stat ni
    sustituirlo) o que nunca almacene el archivo en caché.</p>

    <p>En general, stat o forever es adecuado para producción, y stat o
    never para desarrollo.</p>

    <example><title>Ejemplos:</title>
    <highlight language="config">
LuaCodeCache stat
LuaCodeCache forever
LuaCodeCache never
    </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaHookTranslateName</name>
<description>Proporciona un hook para la fase de traducción de nombres del procesamiento de peticiones</description>
<syntax>LuaHookTranslateName  /path/to/lua/script.lua  hook_function_name [early|late]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<override>All</override>
<compatibility>El tercer argumento opcional es compatible a partir de la versión 2.3.15</compatibility>

<usage><p>
    Añade un hook (en APR_HOOK_MIDDLE) a la fase de traducción de nombres
    del procesamiento de peticiones. La función de hook recibe un único
    argumento, el request_rec, y debe devolver un código de estado, que
    puede ser un código de error HTTP, o las constantes definidas en el
    módulo apache2: apache2.OK, apache2.DECLINED o apache2.DONE. </p>

    <p>Para quienes no conozcan los hooks, básicamente cada hook se
    invocará hasta que uno de ellos devuelva apache2.OK. Si su hook no
    quiere realizar la traducción, simplemente debe devolver
    apache2.DECLINED. Si la petición debe detener su procesamiento,
    entonces debe devolver apache2.DONE.</p>

    <p>Ejemplo:</p>

<highlight language="config">
# httpd.conf
LuaHookTranslateName "/scripts/conf/hooks.lua" silly_mapper
</highlight>

<highlight language="lua">
-- /scripts/conf/hooks.lua --
require "apache2"
function silly_mapper(r)
    if r.uri == "/" then
        r.filename = "/var/www/home.lua"
        return apache2.OK
    else
        return apache2.DECLINED
    end
end
</highlight>

   <note><title>Contexto</title><p>Esta directiva no es válida en el
   contexto <directive type="section" module="core">Directory</directive>,
   <directive type="section" module="core">Files</directive>, ni en
   htaccess.</p></note>

   <note><title>Orden</title><p>Los argumentos opcionales "early" o "late"
   controlan cuándo se ejecuta este script en relación con otros módulos.</p></note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaHookPreTranslate</name>
<description>Proporciona un hook para la fase pre_translate del
procesamiento de peticiones</description>
<syntax>LuaHookPreTranslate  /path/to/lua/script.lua hook_function_name</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<usage>
<p>
    Igual que LuaHookTranslateName, pero se ejecuta en la fase
    pre_translate, donde la ruta de la URI no está decodificada en
    porcentaje.
</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaHookFixups</name>
<description>Proporciona un hook para la fase fixups del
procesamiento de peticiones</description>
<syntax>LuaHookFixups  /path/to/lua/script.lua hook_function_name</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<usage>
<p>
    Igual que LuaHookTranslateName, pero se ejecuta en la fase fixups
</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaHookLog</name>
<description>Proporciona un hook para la fase de log de acceso del
procesamiento de peticiones</description>
<syntax>LuaHookLog  /path/to/lua/script.lua log_function_name</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<usage>
<p>
    Este sencillo hook de registro permite ejecutar una función cuando
    httpd entra en la fase de registro de una petición. Con él puede
    añadir datos a sus propios logs, manipular los datos antes de que se
    escriba el log normal, o impedir que se cree una entrada de log. Para
    evitar el registro habitual, simplemente devuelva
    <code>apache2.DONE</code> en su handler de registro; en caso
    contrario, devuelva <code>apache2.OK</code> para indicar a httpd que
    registre con normalidad.
</p>
<p>Ejemplo:</p>
<highlight language="config">
LuaHookLog "/path/to/script.lua" logger
</highlight>
<highlight language="lua">
-- /path/to/script.lua --
function logger(r)
    -- flip a coin:
    -- If 1, then we write to our own Lua log and tell httpd not to log
    -- in the main log.
    -- If 2, then we just sanitize the output a bit and tell httpd to
    -- log the sanitized bits.

    if math.random(1,2) == 1 then
        -- Log stuff ourselves and don't log in the regular log
        local f = io.open("/foo/secret.log", "a")
        if f then
            f:write("Something secret happened at " .. r.uri .. "\n")
            f:close()
        end
        return apache2.DONE -- Tell httpd not to use the regular logging functions
    else
        r.uri = r.uri:gsub("somesecretstuff", "") -- sanitize the URI
        return apache2.OK -- tell httpd to log it.
    end
end
</highlight>
</usage>
</directivesynopsis>


<directivesynopsis>
<name>LuaHookMapToStorage</name>
<description>Proporciona un hook para la fase map_to_storage del procesamiento de peticiones</description>
<syntax>LuaHookMapToStorage  /path/to/lua/script.lua hook_function_name</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
    <usage>
    <p>Igual que <directive>LuaHookTranslateName</directive> pero se
    ejecuta en la fase map-to-storage de una petición. Módulos como
    <module>mod_cache</module> se ejecutan en esta fase, lo que da lugar a
    un ejemplo interesante de lo que se puede hacer aquí:</p>
    <highlight language="config">
    LuaHookMapToStorage "/path/to/lua/script.lua" check_cache
    </highlight>
    <highlight language="lua">
require"apache2"
cached_files = {}

function read_file(filename)
    local input = io.open(filename, "r")
    if input then
        local data = input:read("*a")
        cached_files[filename] = data
        file = cached_files[filename]
        input:close()
    end
    return cached_files[filename]
end

function check_cache(r)
    if r.filename:match("%.png$") then -- Only match PNG files
        local file = cached_files[r.filename] -- Check cache entries
        if not file then
            file = read_file(r.filename)  -- Read file into cache
        end
        if file then -- If file exists, write it out
            r.status = 200
            r:write(file)
            r:info(("Sent %s to client from cache"):format(r.filename))
            return apache2.DONE -- skip default handler for PNG files
        end
    end
    return apache2.DECLINED -- If we had nothing to do, let others serve this.
end
    </highlight>

    </usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaHookCheckUserID</name>
<description>Proporciona un hook para la fase check_user_id del procesamiento de peticiones</description>
<syntax>LuaHookCheckUserID  /path/to/lua/script.lua hook_function_name [early|late]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>El tercer argumento opcional se admite en la versión 2.3.15 y posteriores</compatibility>
<usage><p>...</p>
   <note><title>Orden</title><p>Los argumentos opcionales "early" o "late"
   controlan cuándo se ejecuta este script en relación con otros módulos.</p></note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaHookTypeChecker</name>
<description>Proporciona un hook para la fase type_checker del procesamiento de peticiones</description>
<syntax>LuaHookTypeChecker  /path/to/lua/script.lua hook_function_name</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
    <usage><p>
    Esta directiva proporciona un hook para la fase type_checker del
    procesamiento de peticiones. En esta fase se asigna a las peticiones
    un tipo de contenido y un handler, por lo que se puede usar para
    modificar el tipo y el handler en función de la entrada:
    </p>
    <highlight language="config">
    LuaHookTypeChecker "/path/to/lua/script.lua" type_checker
    </highlight>
    <highlight language="lua">
    function type_checker(r)
        if r.uri:match("%.to_gif$") then -- match foo.png.to_gif
            r.content_type = "image/gif" -- assign it the image/gif type
            r.handler = "gifWizard"      -- tell the gifWizard module to handle this
            r.filename = r.uri:gsub("%.to_gif$", "") -- fix the filename requested
            return apache2.OK
        end

        return apache2.DECLINED
    end
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaHookAuthChecker</name>
<description>Proporciona un hook para la fase auth_checker del procesamiento de peticiones</description>
<syntax>LuaHookAuthChecker  /path/to/lua/script.lua hook_function_name [early|late]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>El tercer argumento opcional es compatible a partir de la versión 2.3.15</compatibility>
<usage>
<p>Invoca una función lua en la fase auth_checker del procesamiento de una
petición. Esto se puede usar para implementar comprobaciones de
autenticación y autorización arbitrarias. Un ejemplo muy sencillo:
</p>
<highlight language="lua">
require 'apache2'

-- fake authcheck hook
-- If request has no auth info, set the response header and
-- return a 401 to ask the browser for basic auth info.
-- If request has auth info, don't actually look at it, just
-- pretend we got userid 'foo' and validated it.
-- Then check if the userid is 'foo' and accept the request.
function authcheck_hook(r)

   -- look for auth info
   auth = r.headers_in['Authorization']
   if auth ~= nil then
     -- fake the user
     r.user = 'foo'
   end

   if r.user == nil then
      r:debug("authcheck: user is nil, returning 401")
      r.err_headers_out['WWW-Authenticate'] = 'Basic realm="WallyWorld"'
      return 401
   elseif r.user == "foo" then
      r:debug('user foo: OK')
   else
      r:debug("authcheck: user='" .. r.user .. "'")
      r.err_headers_out['WWW-Authenticate'] = 'Basic realm="WallyWorld"'
      return 401
   end
   return apache2.OK
end
</highlight>
   <note><title>Orden</title><p>Los argumentos opcionales "early" o "late"
   controlan cuándo se ejecuta este script en relación con otros módulos.</p></note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaHookAccessChecker</name>
<description>Proporciona un hook para la fase access_checker del procesamiento de peticiones</description>
<syntax>LuaHookAccessChecker  /path/to/lua/script.lua  hook_function_name [early|late]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>El tercer argumento opcional es compatible a partir de la versión 2.3.15</compatibility>
<usage>
<p>Añade su hook a la fase access_checker. Una función de hook de
comprobación de acceso normalmente devuelve OK, DECLINED o
HTTP_FORBIDDEN.</p>
   <note><title>Orden</title><p>Los argumentos opcionales "early" o "late"
   controlan cuándo se ejecuta este script en relación con otros módulos.</p></note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaHookInsertFilter</name>
<description>Proporciona un hook para la fase insert_filter del procesamiento de peticiones</description>
<syntax>LuaHookInsertFilter  /path/to/lua/script.lua hook_function_name</syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
    <usage><p>Aún no implementado</p></usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaInherit</name>
<description>Controla cómo se combinan las secciones de configuración del padre en las de los hijos</description>
<syntax>LuaInherit none|parent-first|parent-last</syntax>
<default>LuaInherit parent-first</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>All</override>
<compatibility>2.4.0 y posteriores</compatibility>
    <usage><p>De forma predeterminada, si se usan directivas LuaHook* en
    secciones de configuración Directory o Location que se superponen, los
    scripts definidos en la sección más específica se ejecutan
    <em>después</em> de los definidos en la sección más genérica
    (LuaInherit parent-first). Puede invertir este orden, o hacer que el
    contexto del padre no se aplique en absoluto.</p>

    <p>En versiones 2.3.x anteriores, el comportamiento predeterminado era,
    en la práctica, ignorar las directivas LuaHook* de las secciones de
    configuración del padre.</p></usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaQuickHandler</name>
<description>Proporciona un hook para el quick handler del procesamiento de peticiones</description>
<syntax>LuaQuickHandler /path/to/script.lua hook_function_name</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<override>All</override>
<usage>
    <p>
    Esta fase se ejecuta inmediatamente después de que la petición se haya
    asociado a un host virtual, y se puede usar para realizar cierto
    procesamiento de la petición antes de que entren en acción las demás
    fases, o para servir una petición sin necesidad de traducirla,
    asociarla al almacenamiento, etc. Como esta fase se ejecuta antes que
    cualquier otra, directivas como <directive
   type="section" module="core">Location</directive> o <directive
   type="section" module="core">Directory</directive> no tienen efecto en
    esta fase, ya que las URIs todavía no se han analizado correctamente.
    </p>
   <note><title>Contexto</title><p>Esta directiva no es válida en el
   contexto <directive type="section" module="core">Directory</directive>,
   <directive type="section" module="core">Files</directive>, ni en
   htaccess.</p></note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaAuthzProvider</name>
<description>Conecta una función de proveedor de autorización a <module>mod_authz_core</module>
</description>
<syntax>LuaAuthzProvider provider_name /path/to/lua/script.lua function_name</syntax>
<contextlist><context>server config</context> </contextlist>
<compatibility>2.4.3 y posteriores</compatibility>

<usage>
<p>Una vez que se ha registrado una función lua como proveedor de
autorización, se puede usar con la directiva
<directive module="mod_authz_core">Require</directive>:</p>

<highlight language="config">
LuaRoot "/usr/local/apache2/lua"
LuaAuthzProvider foo authz.lua authz_check_foo
&lt;Location "/"&gt;
  Require foo johndoe
&lt;/Location&gt;
</highlight>
<highlight language="lua">
require "apache2"
function authz_check_foo(r, who)
    if r.user ~= who then return apache2.AUTHZ_DENIED
    return apache2.AUTHZ_GRANTED
end
</highlight>


</usage>
</directivesynopsis>


<directivesynopsis>
<name>LuaInputFilter</name>
<description>Proporciona una función Lua para el filtrado de entrada de contenido</description>
<syntax>LuaInputFilter filter_name /path/to/lua/script.lua function_name</syntax>
<contextlist><context>server config</context> </contextlist>
<compatibility>2.4.5 y posteriores</compatibility>

<usage>
<p>Proporciona un medio para añadir una función Lua como filtro de
entrada. Igual que los filtros de salida, los filtros de entrada funcionan
como coroutines, primero haciendo yield antes de que se envíen los
buffers, luego haciendo yield cada vez que hay que pasar un bucket por la
cadena, y finalmente (opcionalmente) haciendo yield con cualquier cosa que
haya que añadir a los datos de entrada. La variable global
<code>bucket</code> contiene los buckets a medida que se pasan al script
Lua:
</p>

<highlight language="config">
LuaInputFilter myInputFilter "/www/filter.lua" input_filter
&lt;Files "*.lua"&gt;
  SetInputFilter myInputFilter
&lt;/Files&gt;
</highlight>
<highlight language="lua">
--[[
    Example input filter that converts all POST data to uppercase.
]]--
function input_filter(r)
    print("luaInputFilter called") -- debug print
    coroutine.yield() -- Yield and wait for buckets
    while bucket do -- For each bucket, do...
        local output = string.upper(bucket) -- Convert all POST data to uppercase
        coroutine.yield(output) -- Send converted data down the chain
    end
    -- No more buckets available.
    coroutine.yield("&amp;filterSignature=1234") -- Append signature at the end
end
</highlight>
<p>
El filtro de entrada admite denegar/omitir un filtro si se considera no
deseado:
</p>
<highlight language="lua">
function input_filter(r)
    if not good then
        return -- Simply deny filtering, passing on the original content instead
    end
    coroutine.yield() -- wait for buckets
    ... -- insert filter stuff here
end
</highlight>
<p>
Consulte "<a href="#modifying_buckets">Modificar contenidos con filtros
Lua</a>" para obtener más información.
</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LuaOutputFilter</name>
<description>Proporciona una función Lua para el filtrado de salida de contenido</description>
<syntax>LuaOutputFilter filter_name /path/to/lua/script.lua function_name</syntax>
<contextlist><context>server config</context> </contextlist>
<compatibility>2.4.5 y posteriores</compatibility>

<usage>
<p>Proporciona un medio para añadir una función Lua como filtro de salida.
Igual que los filtros de entrada, los filtros de salida funcionan como
coroutines, primero haciendo yield antes de que se envíen los buffers,
luego haciendo yield cada vez que hay que pasar un bucket por la cadena, y
finalmente (opcionalmente) haciendo yield con cualquier cosa que haya que
añadir a los datos de entrada. La variable global <code>bucket</code>
contiene los buckets a medida que se pasan al script Lua:
</p>

<highlight language="config">
LuaOutputFilter myOutputFilter "/www/filter.lua" output_filter
&lt;Files "*.lua"&gt;
  SetOutputFilter myOutputFilter
&lt;/Files&gt;
</highlight>
<highlight language="lua">
--[[
    Example output filter that escapes all HTML entities in the output
]]--
function output_filter(r)
    coroutine.yield("(Handled by myOutputFilter)&lt;br/&gt;\n") -- Prepend some data to the output,
                                                          -- yield and wait for buckets.
    while bucket do -- For each bucket, do...
        local output = r:escape_html(bucket) -- Escape all output
        coroutine.yield(output) -- Send converted data down the chain
    end
    -- No more buckets available.
end
</highlight>
<p>
Igual que con el filtro de entrada, el filtro de salida admite
denegar/omitir un filtro si se considera no deseado:
</p>
<highlight language="lua">
function output_filter(r)
    if not r.content_type:match("text/html") then
        return -- Simply deny filtering, passing on the original content instead
    end
    coroutine.yield() -- wait for buckets
    ... -- insert filter stuff here
end
</highlight>
<note><title>Filtros Lua con <module>mod_filter</module></title>
<p>Cuando se usa un filtro Lua como proveedor subyacente a través de la
directiva <directive module="mod_filter">FilterProvider</directive>, el
filtrado solo funcionará cuando <var>filter-name</var> sea idéntico a
<var>provider-name</var>.
</p> </note>

<p>
Consulte "<a href="#modifying_buckets">Modificar contenidos con filtros
Lua</a>" para obtener más información.
</p>

</usage>
</directivesynopsis>



</modulesynopsis>
