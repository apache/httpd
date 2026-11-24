<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1861455 -->
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

<modulesynopsis metafile="mod_session_crypto.xml.meta">

<name>mod_session_crypto</name>
<description>Soporte de cifrado de sesiones</description>
<status>Experimental</status>
<sourcefile>mod_session_crypto.c</sourcefile>
<identifier>session_crypto_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
    <note type="warning"><title>Advertencia</title>
      <p>Los módulos de sesión hacen uso de cookies HTTP, y por ello pueden ser
      víctimas de ataques de Cross Site Scripting, o exponer a los clientes información
      potencialmente privada. Asegúrese de haber tenido en cuenta los
      riesgos relevantes antes de activar la funcionalidad de sesión en
      su servidor.</p>
    </note>

    <p>Este submódulo de <module>mod_session</module> proporciona soporte para el
    cifrado de sesiones de usuario antes de escribirlas en una base de datos local, o
    de escribirlas en un navegador remoto mediante una cookie HTTP.</p>

    <p>Esto puede ayudar a proporcionar privacidad a las sesiones de usuario cuando el
    contenido de la sesión deba mantenerse privado respecto al usuario, o cuando se necesite
    protección frente a los efectos de los ataques de cross site scripting.</p>

    <p>Para más detalles sobre la interfaz de sesión, consulte la documentación de
    el módulo <module>mod_session</module>.</p>

</summary>
<seealso><module>mod_session</module></seealso>
<seealso><module>mod_session_cookie</module></seealso>
<seealso><module>mod_session_dbd</module></seealso>

    <section id="basicusage"><title>Uso básico</title>

      <p>Para crear una sesión cifrada sencilla y almacenarla en una cookie llamada
      <var>session</var>, configure la sesión de la siguiente manera:</p>

      <example><title>Sesión cifrada basada en el navegador</title>
      <highlight language="config">
Session On
SessionCookieName session path=/
SessionCryptoPassphrase secret
    </highlight>
      </example>

      <p>La sesión se cifrará con la clave indicada. Pueden configurarse distintos servidores
      para compartir sesiones asegurándose de que se use la misma clave de cifrado
      en cada servidor.</p>

      <p>Si se cambia la clave de cifrado, las sesiones se invalidarán
      automáticamente.</p>

      <p>Para documentación sobre cómo puede usarse la sesión para almacenar el nombre
      de usuario y la contraseña, consulte el módulo <module>mod_auth_form</module>.</p>

    </section>

<directivesynopsis>
<name>SessionCryptoDriver</name>
<description>El driver criptográfico que se usará para cifrar la sesión</description>
<syntax>SessionCryptoDriver <var>name</var> <var>[param[=value]]</var></syntax>
<default>none</default>
<contextlist><context>server config</context>
</contextlist>
<compatibility>Disponible en Apache 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>SessionCryptoDriver</directive> especifica el nombre del
    driver criptográfico que se usará para el cifrado. Si no se especifica, el driver recurre por defecto
    al driver recomendado compilado en APR-util.</p>

    <p>El driver criptográfico <var>NSS</var> requiere algunos parámetros de configuración,
    que se especifican como parámetros con valores opcionales después del nombre del driver.</p>

    <example><title>NSS sin base de datos de certificados</title>
    <highlight language="config">
      SessionCryptoDriver nss
      </highlight>
    </example>

    <example><title>NSS con base de datos de certificados</title>
    <highlight language="config">
      SessionCryptoDriver nss dir=certs
      </highlight>
    </example>

    <example><title>NSS con base de datos de certificados y parámetros</title>
    <highlight language="config">
      SessionCryptoDriver nss dir=certs key3=key3.db cert7=cert7.db secmod=secmod
      </highlight>
    </example>

    <example><title>NSS con rutas que contienen espacios</title>
    <highlight language="config">
      SessionCryptoDriver nss "dir=My Certs" key3=key3.db cert7=cert7.db secmod=secmod
      </highlight>
    </example>

    <p>Es posible que el driver criptográfico <var>NSS</var> ya haya sido
    configurado por otra parte del servidor, por ejemplo desde
    <code>mod_nss</code> o <module>mod_ldap</module>. Si se detecta que
    ya estaba configurado, se registrará una advertencia, y la
    configuración existente surtirá efecto. Para evitar esta
    advertencia, use el parámetro noinit como se muestra a continuación.</p>

    <example><title>NSS con base de datos de certificados</title>
    <highlight language="config">
      SessionCryptoDriver nss noinit
      </highlight>
    </example>

    <p>Para evitar confusiones, asegúrese de que todos los módulos que requieren NSS estén configurados con
    parámetros idénticos.</p>

    <p>El driver criptográfico <var>openssl</var> admite un parámetro opcional para especificar
    el motor que se usará para el cifrado.</p>

    <example><title>OpenSSL con soporte de motor</title>
    <highlight language="config">
      SessionCryptoDriver openssl engine=name
      </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionCryptoPassphrase</name>
<description>La clave usada para cifrar la sesión</description>
<syntax>SessionCryptoPassphrase <var>secret</var> [ <var>secret</var> ... ] </syntax>
<default>none</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible en Apache 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>SessionCryptoPassphrase</directive> especifica las claves
    que se usarán para activar el cifrado simétrico del contenido de la sesión antes de
    escribirla, o para descifrar el contenido de la sesión tras leerla.</p>

    <p>Las claves son más seguras cuando son largas y están formadas por caracteres verdaderamente aleatorios.
    Cambiar la clave en un servidor tiene el efecto de invalidar todas las sesiones
    existentes.</p>

    <p>Pueden especificarse varias claves para permitir la rotación de claves. La primera clave
    de la lista se usará para el cifrado, mientras que se intentará usar todas las claves listadas para el
    descifrado. Para rotar claves entre varios servidores a lo largo del tiempo, añada un nuevo
    secreto al final de la lista, y una vez desplegado por completo en todos los servidores, elimine
    la primera clave del principio de la lista.</p>

    <p>A partir de la versión 2.4.7, si el valor empieza por <var>exec:</var> se ejecutará el
    comando resultante y se usará como clave la primera línea que el programa devuelva en la
    salida estándar.</p>
<example>
    <highlight language="config">
#clave usada tal cual
SessionCryptoPassphrase secret

#Ejecutar /ruta/al/programa para obtener la clave
SessionCryptoPassphrase exec:/path/to/program

#Ejecutar /ruta/a/otroPrograma y proporcionar argumentos
SessionCryptoPassphrase "exec:/path/to/otherProgram argument1"
    </highlight>
</example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionCryptoPassphraseFile</name>
<description>Archivo que contiene las claves usadas para cifrar la sesión</description>
<syntax>SessionCryptoPassphraseFile <var>filename</var></syntax>
<default>none</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
</contextlist>
<compatibility>Disponible en Apache 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>SessionCryptoPassphraseFile</directive> especifica el
    nombre de un archivo de configuración que contiene las claves que se usarán para cifrar o descifrar
    la sesión, especificadas una por línea. El archivo se lee al arrancar el servidor, y será
    necesario un reinicio ordenado (graceful) para que httpd detecte los cambios en las claves.</p>

    <p>A diferencia de la directiva <directive module="mod_session_crypto">SessionCryptoPassphrase</directive>, las claves
    no quedan expuestas en la configuración de httpd y pueden ocultarse protegiendo el archivo
    adecuadamente.</p>

    <p>Pueden especificarse varias claves para permitir la rotación de claves. La primera clave
    de la lista se usará para el cifrado, mientras que se intentará usar todas las claves listadas para el
    descifrado. Para rotar claves entre varios servidores a lo largo del tiempo, añada un nuevo
    secreto al final de la lista, y una vez desplegado por completo en todos los servidores, elimine
    la primera clave del principio de la lista.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionCryptoCipher</name>
<description>El cifrador criptográfico que se usará para cifrar la sesión</description>
<syntax>SessionCryptoCipher <var>name</var></syntax>
<default>SessionCryptoCipher aes256</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible en Apache 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>SessionCryptoCipher</directive> permite indicar el cifrador que
    se usará durante el cifrado. Si no se especifica, el cifrador recurre por defecto a
    <code>aes256</code>.</p>

    <p>Los valores posibles dependen del driver criptográfico en uso, y pueden ser uno de:</p>

    <ul><li>3des192</li><li>aes128</li><li>aes192</li><li>aes256</li></ul>

</usage>
</directivesynopsis>

</modulesynopsis>
