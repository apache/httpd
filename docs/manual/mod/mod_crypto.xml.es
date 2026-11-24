<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933830 -->
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

<modulesynopsis metafile="mod_crypto.xml.meta">

<name>mod_crypto</name>
<description>Soporte para cifrado y descifrado simétrico</description>
<status>Extension</status>
<sourcefile>mod_crypto.c</sourcefile>
<identifier>crypto_module</identifier>
<compatibility>Disponible en Apache 2.5 y posteriores</compatibility>

<summary>
    <p>Este módulo proporciona la capacidad de <strong>cifrar y descifrar</strong>
    datos en las pilas de filtros de entrada y de salida.</p>

    <p>Más concretamente, se puede usar para implementar <strong>cifrado HLS
    al vuelo</strong> según se describe en
    <a href="http://www.ietf.org/id/draft-pantos-http-live-streaming-19.txt">
    draft-pantos-http-live-streaming-19</a>.</p>

    <p>Alternativamente, se puede usar para entregar datos seguros a través de una CDN
    insegura a clientes adecuados.</p>

    <p>El filtro de cifrado se puede añadir tanto a la pila de filtros de entrada como a la
    de salida, según corresponda, usando las directivas
    <directive module="core">SetInputFilter</directive>,
    <directive module="core">SetOutputFilter</directive>,
    <directive module="mod_mime">AddOutputFilter</directive> o
    <directive module="mod_filter">AddOutputFilterByType</directive>.</p>

</summary>
<seealso><a href="../filter.html">Filtros</a></seealso>

<section id="format">
    <title>Formato del flujo</title>

    <p>El flujo cifrado consiste en un bloque IV opcional, seguido de bloques cifrados
    usando el cifrador elegido. El último bloque se rellena antes de escribirse. El
    tamaño de los bloques depende del cifrador elegido.</p>

    <p>Cuando el IV se especifica con la directiva <directive module="mod_crypto">CryptoIV</directive>,
    se usa ese IV, y no se escribe en el flujo ni se lee de él.</p>

</section>

<section id="config">
    <title>Claves e IVs</title>

    <p>
        Las directivas
        <directive module="mod_crypto">CryptoKey</directive>
        y
        <directive module="mod_crypto">CryptoIV</directive>
        esperan valores binarios que se pueden especificar de varias formas, como se indica a continuación. Se
        usan los bits más significativos de los valores correspondientes, y si los valores son
        demasiado cortos, se rellenan por la izquierda con bits a cero.
    </p>

    <dl>
    <dt>file:</dt><dd>Lee el valor directamente del archivo indicado.</dd>
    <dt>hex:</dt><dd>Interpreta la expresión como un valor hexadecimal, que puede contener separadores de dos puntos.</dd>
    <dt>decimal:</dt><dd>Interpreta la expresión como un valor decimal.</dd>
    <dt>base64:</dt><dd>Interpreta la expresión como un valor base64.</dd>
    <dt>none</dt><dd>No se especifica ningún valor.</dd>
    </dl>

    <p>Si no se especifica el IV, se generará un IV aleatorio durante
        el cifrado y se escribirá como el primer bloque. Durante el descifrado, el primer
        bloque se interpretará como el IV.
    </p>

    <p>Con la excepción de file:, las directivas <directive module="mod_crypto">CryptoKey</directive>
       y <directive module="mod_crypto">CryptoIV</directive> permiten usar
       <a href="../expr.html">sintaxis de expresión</a> para aportar flexibilidad al establecer los valores.
       Esto permite que tanto las claves como los IVs se "salen" con valores disponibles para el servidor web, como
       REMOTE_USER, o la URL.
    </p>

</section>

<section id="handler">
    <title>Manejador de clave de cifrado</title>

    <p>Por comodidad, el manejador <strong>crypto-key</strong> se puede usar para servir la clave
    a los clientes debidamente autorizados, eliminando la necesidad de almacenar la clave dentro del espacio
    de directorios del servidor web. Esto también permite usar la misma <a href="../expr.html">sintaxis
    de expresión</a> para derivar la clave tanto para los clientes como para el contenido cifrado.</p>

    <example><title>Manejador de clave de cifrado con un archivo</title>
      &lt;Location /key&gt;<br />
      <indent>
        SetHandler crypto-key<br />
        CryptoCipher aes128<br />
        CryptoKey file:/path/to/file.key<br />
        AuthType basic<br />
        ...<br />
        </indent>
      &lt;/Location&gt;<br />
    </example>

</section>

<section id="hls">
    <title>HTTP Live Streaming</title>

    <p>El protocolo HLS admite flujos cifrados usando el cifrador AES-128 y una
    clave correspondiente. El acceso al flujo se concede compartiendo la clave con
    el cliente HLS, normalmente a través de una conexión segura.</p>

    <p>El IV usado para cifrar cada segmento multimedia se especifica dentro
        de HLS de una de estas dos formas:</p>

    <ul>
        <li>
            Explícitamente, especificado dentro de un atributo IV dentro de la etiqueta
            EXT-X-KEY como un valor <strong>hexadecimal</strong>.
        </li>
        <li>
            Implícitamente, especificado interpretando el valor <strong>decimal</strong>
            de la etiqueta EXT-X-MEDIA-SEQUENCE.
        </li>
    </ul>

    <p>El valor de la secuencia multimedia suele estar incluido en los nombres
        de los archivos de los segmentos multimedia, y se puede capturar usando
        expresiones regulares con nombre, como en el ejemplo siguiente.
    </p>

    <example><title>Ejemplo de HLS: IV a partir de la secuencia multimedia</title>
      &lt;LocationMatch (?&lt;SEQUENCE&gt;[\d]+)[^\d^/]+$&gt;<br />
      <indent>
        SetOutputFilter ENCRYPT<br />
        CryptoCipher aes128<br />
        CryptoKey file:/path/to/file.key<br />
        CryptoIV decimal:%{env:MATCH_SEQUENCE}<br />
        </indent>
      &lt;/LocationMatch&gt;<br />
    </example>

</section>

<directivesynopsis>
<name>CryptoDriver</name>
<description>Nombre del driver de cifrado a usar</description>
<syntax>CryptoDriver name</syntax>
<default>CryptoDriver openssl</default>
<contextlist><context>server config</context>
</contextlist>

<usage>
    <p>La directiva <directive module="mod_crypto">CryptoDriver</directive>
    especifica el nombre del driver de cifrado a usar. Normalmente hay
    un driver por defecto recomendado en cada plataforma. Entre los valores posibles están
    <strong>openssl</strong>, <strong>commoncrypto</strong> y
    <strong>nss</strong>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CryptoCipher</name>
<description>Cifrador que usará el filtro de cifrado</description>
<syntax>CryptoCipher name</syntax>
<default>CryptoCipher aes256</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>CryptoCipher</directive> permite especificar
    el cifrador que se usará durante el cifrado o el descifrado. Si no se especifica, el
    cifrador por defecto es <code>aes256</code>.</p>

    <p>Los valores posibles dependen del driver de cifrado en uso, y pueden ser uno de los siguientes:</p>

    <ul><li>3des192</li><li>aes128</li><li>aes192</li><li>aes256</li></ul>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CryptoIV</name>
<description>IV (vector de inicialización) que usará el filtro de cifrado</description>
<syntax>CryptoIV value</syntax>
<default>CryptoIV none</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>CryptoIV</directive> permite especificar el IV (vector
    de inicialización) para un espacio de URLs concreto. El IV se puede leer de
    un archivo, o se puede establecer basándose en el <a href="../expr.html">analizador de expresiones</a>,
    lo que permite escenarios flexibles para el establecimiento de claves.</p>

    <p>Los valores se pueden especificar como lectura de un archivo, o como un valor hexadecimal, decimal o
    base64, según los siguientes prefijos:</p>

    <ul><li>file:</li><li>hex:</li><li>decimal:</li><li>base64:</li></ul>

    <p>El valor 'none' desactiva el establecimiento del IV. En este caso, durante el cifrado
    se generará un IV aleatorio y se insertará como primer bloque, y durante el
    descifrado el primer bloque se interpretará como el IV.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CryptoKey</name>
<description>Clave que usará el filtro de cifrado</description>
<syntax>CryptoKey value</syntax>
<default>CryptoKey none</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>CryptoKey</directive> permite especificar la clave de
    cifrado/descifrado para un espacio de URLs concreto. La clave se puede leer de un archivo, o
    se puede establecer basándose en el <a href="../expr.html">analizador de expresiones</a>, lo que permite
    escenarios flexibles para el establecimiento de claves.</p>

    <p>Los valores se pueden especificar como lectura de un archivo, o como un valor hexadecimal, decimal o
    base64, según los siguientes prefijos:</p>

    <ul><li>file:</li><li>hex:</li><li>decimal:</li><li>base64:</li></ul>

    <p>El valor 'none' desactiva la clave. Un intento de servir un archivo a través de los filtros ENCRYPT
    o DECRYPT sin una clave hará que la petición falle.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CryptoSize</name>
<description>Tamaño máximo en bytes que almacena en búfer el filtro de cifrado</description>
<syntax>CryptoSize integer</syntax>
<default>CryptoSize 131072</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive module="mod_crypto">CryptoSize</directive>
    especifica la cantidad de datos en bytes que se almacenarán en búfer
    antes de cifrarse o descifrarse en cada petición.
    El valor por defecto es 128 kilobytes.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
