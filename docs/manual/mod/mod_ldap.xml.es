<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933764 -->
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

<modulesynopsis metafile="mod_ldap.xml.meta">

<name>mod_ldap</name>
<description>Servicios de agrupación de conexiones LDAP y caché de
resultados para uso de otros módulos LDAP</description>
<status>Extension</status>
<sourcefile>util_ldap.c</sourcefile>
<identifier>ldap_module</identifier>

<summary>
    <p>Este módulo se creó para mejorar el rendimiento de los
    sitios web que dependen de conexiones de backend a servidores LDAP. Además
    de las funciones proporcionadas por las bibliotecas LDAP estándar, este
    módulo añade un pool de conexiones LDAP y una caché LDAP en memoria
    compartida.</p>

    <p>Para activar este módulo, el soporte LDAP debe estar compilado
    en apr-util. Esto se consigue añadiendo el flag
    <code>--with-ldap</code> al script <program>configure</program> al
    compilar Apache.</p>

    <p>El soporte SSL/TLS depende de qué toolkit LDAP esté
    enlazado a <glossary>APR</glossary>. En el momento de escribir esto, APR-util soporta:
    <a href="http://www.openldap.org/">OpenLDAP SDK</a> (2.x o posterior),
    <a href="https://wiki.mozilla.org/LDAP_C_SDK">Mozilla LDAP SDK</a>, el SDK LDAP nativo de Solaris (basado en Mozilla) o el
    SDK LDAP nativo de Microsoft. Consulte el sitio web de
    <a href="http://apr.apache.org">APR</a> para más detalles.</p>

</summary>

<section id="exampleconfig"><title>Ejemplo de configuración</title>
    <p>A continuación se muestra un ejemplo de configuración que usa
    <module>mod_ldap</module> para aumentar el rendimiento de la autenticación
    HTTP Basic proporcionada por <module>mod_authnz_ldap</module>.</p>

    <highlight language="config">
# Activa el pool de conexiones LDAP y la caché en
# memoria compartida. Activa el manejador de estado de
# la caché LDAP. Requiere que mod_ldap y mod_authnz_ldap
# estén cargados. Cambie "yourdomain.example.com" para
# que coincida con su dominio.

LDAPSharedCacheSize 500000
LDAPCacheEntries 1024
LDAPCacheTTL 600
LDAPOpCacheEntries 1024
LDAPOpCacheTTL 600

&lt;Location "/ldap-status"&gt;
    SetHandler ldap-status

    Require host yourdomain.example.com

    Satisfy any
    AuthType Basic
    AuthName "LDAP Protected"
    AuthBasicProvider ldap
    AuthLDAPURL ldap://127.0.0.1/dc=example,dc=com?uid?one
    Require valid-user
&lt;/Location&gt;
    </highlight>
</section>

<section id="pool"><title>Pool de conexiones LDAP</title>

    <p>Las conexiones LDAP se agrupan de petición a petición. Esto
    permite que el servidor LDAP permanezca conectado y listo para
    la siguiente petición, sin necesidad de desvincular/conectar/revincular.
    Las ventajas de rendimiento son similares al efecto de los keepalives
    de HTTP.</p>

    <p>En un servidor con mucha carga es posible que varias peticiones intenten
    acceder simultáneamente a la misma conexión al servidor LDAP.
    Cuando una conexión LDAP está en uso, Apache creará una nueva
    conexión junto a la original. Esto garantiza que el
    pool de conexiones no se convierta en un cuello de botella.</p>

    <p>No es necesario activar manualmente la agrupación de conexiones en
    la configuración de Apache. Cualquier módulo que use este módulo para
    acceder a servicios LDAP compartirá el pool de conexiones.</p>

    <p>Las conexiones LDAP pueden hacer un seguimiento de las credenciales
    de cliente LDAP usadas al vincularse a un servidor LDAP. Estas
    credenciales se pueden proporcionar a servidores LDAP que no
    permitan vinculaciones anónimas durante el seguimiento de referencias (referrals). Para
    controlar esta característica, consulte las directivas
    <directive module="mod_ldap">LDAPReferrals</directive> y
    <directive module="mod_ldap">LDAPReferralHopLimit</directive>.
    Por defecto, esta característica está activada.</p>
</section>

<section id="cache"><title>Caché de LDAP</title>

    <p>Para mejorar el rendimiento, <module>mod_ldap</module> usa una estrategia
    de caché agresiva para minimizar el número de veces que hay que
    contactar con el servidor LDAP. El uso de caché puede fácilmente duplicar o triplicar
    el rendimiento de Apache cuando sirve páginas protegidas
    con <module>mod_authnz_ldap</module>. Además, la carga en el servidor LDAP
    se reducirá de forma significativa.</p>

    <p><module>mod_ldap</module> soporta dos tipos de caché LDAP durante
    la fase de búsqueda/vinculación con una <em>caché de búsqueda/vinculación</em> y
    durante la fase de comparación con dos <em>cachés de
    operación</em>. Cada URL LDAP usada por el servidor tiene
    su propio conjunto de estas tres cachés.</p>

    <section id="search-bind"><title>La caché de búsqueda/vinculación</title>
      <p>El proceso de hacer una búsqueda y después una vinculación es el
      aspecto más costoso en tiempo de las operaciones LDAP, especialmente si
      el directorio es grande. La caché de búsqueda/vinculación se usa para
      cachear todas las búsquedas que resultaron en vinculaciones exitosas.
      Los resultados negativos (<em>es decir</em>, búsquedas sin éxito, o búsquedas
      que no resultaron en una vinculación exitosa) no se cachean.
      La razón de esta decisión es que las conexiones con
      credenciales no válidas son solo un pequeño porcentaje del total
      de conexiones, por lo que al no cachear las credenciales
      no válidas, se reduce el tamaño de la caché.</p>

      <p><module>mod_ldap</module> guarda en la caché el nombre de usuario, el DN
      obtenido, la contraseña usada para la vinculación y el momento de la
      vinculación. Cada vez que se inicia una nueva conexión con el
      mismo nombre de usuario, <module>mod_ldap</module> compara la contraseña
      de la nueva conexión con la contraseña que hay en la caché. Si las
      contraseñas coinciden, y si la entrada cacheada no es demasiado antigua,
      <module>mod_ldap</module> omite la fase de búsqueda/vinculación.</p>

      <p>La caché de búsqueda y vinculación se controla con las directivas
      <directive module="mod_ldap">LDAPCacheEntries</directive> y <directive
      module="mod_ldap">LDAPCacheTTL</directive>.</p>
    </section>

    <section id="opcaches"><title>Cachés de operación</title>
      <p>Durante las funciones de comparación de atributos y de nombres
      distinguidos, <module>mod_ldap</module> usa dos cachés de operación
      para cachear las comparaciones. La primera caché de comparación se
      usa para cachear los resultados de las comparaciones hechas para comprobar
      la pertenencia a grupos LDAP. La segunda caché de comparación se usa para
      cachear los resultados de las comparaciones hechas entre nombres
      distinguidos.</p>

      <p>Tenga en cuenta que, cuando se comprueba la pertenencia a un grupo, los resultados
      de cualquier comparación de subgrupo se cachean para acelerar futuras comparaciones de subgrupos.</p>

      <p>El comportamiento de ambas cachés se controla con
      las directivas <directive module="mod_ldap">LDAPOpCacheEntries</directive>
      y <directive module="mod_ldap">LDAPOpCacheTTL</directive>.</p>
    </section>

    <section id="monitoring"><title>Monitorizar la caché</title>
      <p><module>mod_ldap</module> tiene un manejador de contenido que permite
      a los administradores monitorizar el rendimiento de la caché. El nombre
      del manejador de contenido es <code>ldap-status</code>, así que las
      siguientes directivas podrían usarse para acceder a la
      información de caché de <module>mod_ldap</module>:</p>

      <highlight language="config">
&lt;Location "/server/cache-info"&gt;
    SetHandler ldap-status
&lt;/Location&gt;
      </highlight>

      <p>Al acceder a la URL <code>http://servername/cache-info</code>,
      el administrador puede obtener un informe de estado de cada caché usada
      por <module>mod_ldap</module>. Tenga en cuenta que si Apache no
      soporta memoria compartida, cada instancia de <program>httpd</program> tiene
      su propia caché, por lo que al recargar la URL se obtendrá información
      diferente cada vez, dependiendo de qué instancia de <program>httpd</program>
      procese la petición.</p>
    </section>
</section>

<section id="usingssltls"><title>Usar SSL/TLS</title>

    <p>La posibilidad de crear conexiones SSL y TLS a un servidor LDAP
    se define mediante las directivas
    <directive module="mod_ldap">LDAPTrustedGlobalCert</directive>,
    <directive module="mod_ldap">LDAPTrustedClientCert</directive>
     y <directive module="mod_ldap">LDAPTrustedMode</directive>.
    Estas directivas especifican la CA y los certificados de cliente opcionales a usar,
    así como el tipo de cifrado a usar en la conexión (ninguno, SSL o
    TLS/STARTTLS).</p>

    <highlight language="config">
# Establece una conexión SSL LDAP en el puerto 636. Requiere que
# mod_ldap y mod_authnz_ldap estén cargados. Cambie
# "yourdomain.example.com" para que coincida con su dominio.

LDAPTrustedGlobalCert CA_DER /certs/certfile.der

&lt;Location "/protected"&gt;
    AuthType Basic
    AuthName "LDAP Protected"
    AuthBasicProvider ldap
    AuthLDAPURL ldaps://127.0.0.1/dc=example,dc=com?uid?one
    Require valid-user
&lt;/Location&gt;
    </highlight>

    <highlight language="config">
# Establece una conexión TLS LDAP en el puerto 389. Requiere que
# mod_ldap y mod_authnz_ldap estén cargados. Cambie
# "yourdomain.example.com" para que coincida con su dominio.

LDAPTrustedGlobalCert CA_DER /certs/certfile.der

&lt;Location "/protected"&gt;
    AuthType Basic
    AuthName "LDAP Protected"
    AuthBasicProvider ldap
    AuthLDAPURL ldap://127.0.0.1/dc=example,dc=com?uid?one TLS
    Require valid-user
&lt;/Location&gt;
    </highlight>

</section>

<section id="settingcerts"><title>Certificados SSL/TLS</title>

    <p>Los distintos SDKs de LDAP tienen métodos muy diferentes de establecer
    y gestionar tanto los certificados de CA como los de cliente.</p>

    <p>Si va a usar SSL o TLS, lea esta sección CON ATENCIÓN para
    entender las diferencias entre las configuraciones de los distintos
    toolkits LDAP soportados.</p>

    <section id="settingcerts-netscape"><title>SDK de Netscape/Mozilla/iPlanet</title>
        <p>Los certificados de CA se especifican dentro de un archivo llamado cert7.db.
        El SDK no hablará con ningún servidor LDAP cuyo certificado no
        esté firmado por una CA especificada en ese archivo. Si
        se requieren certificados de cliente, se puede especificar un archivo key3.db
        opcional con una contraseña opcional. El archivo secmod se puede
        especificar si es necesario. Estos archivos están en el mismo formato
        usado por los navegadores Netscape Communicator o Mozilla. La forma más
        fácil de obtener estos archivos es extraerlos de su instalación del
        navegador.</p>

        <p>Los certificados de cliente se especifican por conexión usando la
        directiva <directive module="mod_ldap">LDAPTrustedClientCert</directive>
        haciendo referencia al "nickname" del certificado. Se puede
        especificar una contraseña opcional para desbloquear la clave privada del
        certificado.</p>

        <p>El SDK solo soporta SSL. Un intento de usar STARTTLS provocará
        un error al intentar contactar con el servidor LDAP en
        tiempo de ejecución.</p>

        <highlight language="config">
# Especifica un archivo de certificado de CA de Netscape
LDAPTrustedGlobalCert CA_CERT7_DB /certs/cert7.db
# Especifica un archivo key3.db opcional para soporte de certificado de cliente
LDAPTrustedGlobalCert CERT_KEY3_DB /certs/key3.db
# Especifica el archivo secmod si es necesario
LDAPTrustedGlobalCert CA_SECMOD /certs/secmod
&lt;Location "/protected"&gt;
    AuthType Basic
    AuthName "LDAP Protected"
    AuthBasicProvider ldap
    LDAPTrustedClientCert CERT_NICKNAME &lt;nickname&gt; [password]
    AuthLDAPURL ldaps://127.0.0.1/dc=example,dc=com?uid?one
    Require valid-user
&lt;/Location&gt;
        </highlight>

    </section>

    <section id="settingcerts-openldap"><title>SDK de OpenLDAP</title>

        <p>Debe especificarse uno o más certificados de CA para que el SDK
        de OpenLDAP funcione correctamente. Estos certificados pueden especificarse
        como archivos binarios DER o codificados en Base64 (PEM).</p>

        <p>Tanto los certificados de CA como los de cliente pueden especificarse
        de forma global (<directive module="mod_ldap">LDAPTrustedGlobalCert</directive>) o
        por conexión (<directive module="mod_ldap">LDAPTrustedClientCert</directive>).
        Cuando se especifica cualquier configuración por conexión, la configuración
        global queda sustituida.</p>

        <p>La documentación del SDK afirma soportar tanto SSL como
        STARTTLS, sin embargo STARTTLS no parece funcionar en todas las versiones
        del SDK. El modo SSL/TLS se puede establecer usando el
        parámetro LDAPTrustedMode. Si se especifica una URL ldaps://,
        se fuerza el modo SSL. La documentación de OpenLDAP señala que el soporte
        SSL (ldaps://) se ha declarado obsoleto en favor de TLS,
        aunque la funcionalidad SSL todavía funciona.</p>

        <highlight language="config">
# Especifica dos archivos de certificado de CA
LDAPTrustedGlobalCert CA_DER /certs/cacert1.der
LDAPTrustedGlobalCert CA_BASE64 /certs/cacert2.pem
&lt;Location "/protected"&gt;
    AuthType Basic
    AuthName "LDAP Protected"
    AuthBasicProvider ldap
    LDAPTrustedClientCert CERT_BASE64 /certs/cert1.pem
    LDAPTrustedClientCert KEY_BASE64 /certs/key1.pem
    # Certificados de CA reespecificados debido a certificados de cliente por directorio
    LDAPTrustedClientCert CA_DER /certs/cacert1.der
    LDAPTrustedClientCert CA_BASE64 /certs/cacert2.pem
    AuthLDAPURL ldaps://127.0.0.1/dc=example,dc=com?uid?one
    Require valid-user
&lt;/Location&gt;
        </highlight>

    </section>

    <section id="settingcerts-solaris"><title>SDK de Solaris</title>

        <p>SSL/TLS para las bibliotecas LDAP nativas de Solaris todavía no
        está soportado. Si lo necesita, instale y use las bibliotecas
        de OpenLDAP en su lugar.</p>

    </section>

    <section id="settingcerts-microsoft"><title>SDK de Microsoft</title>

        <p>La configuración de certificados SSL/TLS para las bibliotecas LDAP
        nativas de Microsoft se hace dentro del registro del sistema, y no se
        requieren directivas de configuración.</p>

        <p>Tanto SSL como TLS están soportados usando el formato de URL
        ldaps://, o usando la directiva <directive module="mod_ldap"
        >LDAPTrustedMode</directive> correspondiente.</p>

        <p>Nota: El estado del soporte para certificados de cliente todavía no se
        conoce para este toolkit.</p>

    </section>

</section>

<directivesynopsis>
<name>LDAPSharedCacheSize</name>
<description>Tamaño en bytes de la caché en memoria compartida</description>
<syntax>LDAPSharedCacheSize <var>bytes</var></syntax>
<default>LDAPSharedCacheSize 500000</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Especifica el número de bytes a reservar para la caché en
    memoria compartida. El valor por defecto es 500kb. Si se establece en 0, no se
    usará caché en memoria compartida y cada proceso HTTPD creará su
    propia caché.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPSharedCacheFile</name>
<description>Establece el archivo de la caché en memoria compartida</description>
<syntax>LDAPSharedCacheFile <var>file-path</var></syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Especifica la ruta del archivo de la caché en memoria compartida. Si no se establece,
    se usará memoria compartida anónima si la plataforma lo soporta.</p>

    <p>Si <var>file-path</var> no es una ruta absoluta, la ubicación especificada
    será relativa al valor de
    <directive module="core">DefaultRuntimeDir</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPCacheEntries</name>
<description>Número máximo de entradas en la caché LDAP primaria</description>
<syntax>LDAPCacheEntries <var>number</var></syntax>
<default>LDAPCacheEntries 1024</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Especifica el tamaño máximo de la caché LDAP primaria. Esta
    caché contiene las búsquedas/vinculaciones exitosas. Establézcalo en 0 para desactivar
    el caché de búsqueda/vinculación. El tamaño por defecto es 1024 búsquedas
    cacheadas.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPCacheTTL</name>
<description>Tiempo durante el que los elementos cacheados permanecen válidos</description>
<syntax>LDAPCacheTTL <var>seconds</var></syntax>
<default>LDAPCacheTTL 600</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Especifica el tiempo (en segundos) durante el que un elemento en la
    caché de búsqueda/vinculación permanece válido. El valor por defecto es 600 segundos (10
    minutos).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPOpCacheEntries</name>
<description>Número de entradas usadas para cachear operaciones de
comparación LDAP</description>
<syntax>LDAPOpCacheEntries <var>number</var></syntax>
<default>LDAPOpCacheEntries 1024</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Esto especifica el número de entradas que <module>mod_ldap</module>
    usará para cachear operaciones de comparación LDAP. El valor por defecto es 1024
    entradas. Establecerlo en 0 desactiva el caché de operaciones.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPOpCacheTTL</name>
<description>Tiempo durante el que las entradas de la caché de operaciones permanecen
válidas</description>
<syntax>LDAPOpCacheTTL <var>seconds</var></syntax>
<default>LDAPOpCacheTTL 600</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Especifica el tiempo (en segundos) durante el que las entradas de la
    caché de operaciones permanecen válidas. El valor por defecto es 600 segundos.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPReferralHopLimit</name>
<description>El número máximo de saltos de referencia (referral) a seguir antes de terminar una consulta LDAP.</description>
<syntax>LDAPReferralHopLimit <var>number</var></syntax>
<default>Depende del SDK, normalmente entre 5 y 10</default>
<contextlist><context>directory</context><context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>
    <p>Esta directiva, si está activada por la directiva <directive module="mod_ldap">LDAPReferrals</directive>,
    limita el número de saltos de referencia que se siguen antes de terminar una
    consulta LDAP.</p>

<note type="warning">
<p>El soporte para este parámetro ajustable es poco común en los SDKs de LDAP.</p>
</note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPReferrals</name>
<description>Activa el seguimiento de referencias (referrals) durante las consultas al servidor LDAP.</description>
<syntax>LDAPReferrals On|Off|default</syntax>
<default>LDAPReferrals On</default>
<contextlist><context>directory</context><context>.htaccess</context></contextlist>
<override>AuthConfig</override>
<compatibility>El parámetro <var>default</var> está disponible en Apache 2.4.7 y posteriores</compatibility>

<usage>
    <p>Algunos servidores LDAP dividen su directorio entre varios dominios y usan referencias
    para dirigir a un cliente cuando se cruza un límite de dominio. Esto es similar a una redirección HTTP.
    Las bibliotecas cliente de LDAP pueden o no seguir las referencias por defecto. Esta directiva
    configura explícitamente el seguimiento de referencias en el SDK subyacente.</p>


    <p><directive>LDAPReferrals</directive> admite los siguientes valores:</p>
    <dl>
     <dt>"on"</dt>
     <dd> <p> Cuando se establece en "on", el estado de seguimiento de referencias del SDK
              subyacente se activa, <directive module="mod_ldap">LDAPReferralHopLimit</directive> se usa
              para sobrescribir el límite de saltos del SDK, y se registra una
              llamada de retorno (callback) de revinculación LDAP.</p></dd>
     <dt>"off"</dt>
     <dd> <p> Cuando se establece en "off", el estado de seguimiento de referencias del SDK
              subyacente se desactiva completamente.</p></dd>
     <dt>"default"</dt>
     <dd> <p> Cuando se establece en "default", el estado de seguimiento de referencias del SDK
              subyacente no se modifica, <directive module="mod_ldap">LDAPReferralHopLimit</directive> no se
              usa para sobrescribir el límite de saltos del SDK, y no se registra ninguna
              llamada de retorno (callback) de revinculación LDAP.</p></dd>
    </dl>

    <p>La directiva <directive module="mod_ldap">LDAPReferralHopLimit</directive> funciona junto con
    esta directiva para limitar el número de saltos de referencia a seguir antes de terminar la consulta LDAP.
    Cuando el procesamiento de referencias está activado con el valor "On", se proporcionarán credenciales de cliente,
    mediante una llamada de retorno de revinculación, a cualquier servidor LDAP que las requiera.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPRetryDelay</name>
<description>Configura el retardo entre reintentos al servidor LDAP.</description>
<syntax>LDAPRetryDelay <var>seconds</var></syntax>
<default>LDAPRetryDelay 0</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Si <directive>LDAPRetryDelay</directive> se establece en un valor
    distinto de cero, el servidor retrasará el reintento de una petición LDAP durante
    el tiempo especificado. Establecer esta directiva en 0 hará
    que cualquier reintento se produzca sin retardo.</p>

    <p>Errores LDAP como los tiempos de espera agotados y las conexiones rechazadas son reintentables.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPRetries</name>
<description>Configura el número de reintentos al servidor LDAP.</description>
<syntax>LDAPRetries <var>number-of-retries</var></syntax>
<default>LDAPRetries 3</default>
<contextlist><context>server config</context></contextlist>
<usage>
    <p>El servidor reintentará las peticiones LDAP fallidas hasta
    <directive>LDAPRetries</directive> veces. Establecer esta
    directiva en 0 desactiva los reintentos.</p>
    <p>Errores LDAP como los tiempos de espera agotados y las conexiones rechazadas son reintentables.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPTrustedGlobalCert</name>
<description>Establece el archivo o base de datos que contiene la Autoridad de
Certificación de confianza global o los certificados de cliente globales</description>
<syntax>LDAPTrustedGlobalCert <var>type</var> <var>directory-path/filename</var> <var>[password]</var></syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Especifica la ruta y el nombre del archivo de los certificados de CA
    de confianza y/o de los certificados de cliente a nivel de todo el sistema que <module>mod_ldap</module>
    debe usar al establecer una conexión SSL o TLS a un servidor
    LDAP. Tenga en cuenta que toda la información de certificados especificada con esta directiva
    se aplica globalmente a toda la instalación del servidor. Algunos toolkits LDAP
    (en particular Novell) requieren que todos los certificados de cliente se establezcan globalmente usando
    esta directiva. La mayoría de los demás toolkits requieren que los certificados de cliente se establezcan
    por Directory o por Location usando <directive module="mod_ldap"
    >LDAPTrustedClientCert</directive>. Si se equivoca en esto, puede registrarse
    un error al intentar contactar con el servidor LDAP, o la conexión puede fallar
    silenciosamente (consulte la guía de certificados SSL/TLS anterior para más detalles).
    El tipo especifica la clase de parámetro de certificado que se está
    estableciendo, dependiendo del toolkit LDAP usado. Los tipos soportados son:</p>
    <ul>
      <li>CA_DER - certificado de CA binario codificado en DER</li>
      <li>CA_BASE64 - certificado de CA codificado en PEM</li>
      <li>CA_CERT7_DB - archivo de base de datos de certificados de CA cert7.db de Netscape</li>
      <li>CA_SECMOD - archivo de base de datos secmod de Netscape</li>
      <li>CERT_DER - certificado de cliente binario codificado en DER</li>
      <li>CERT_BASE64 - certificado de cliente codificado en PEM</li>
      <li>CERT_KEY3_DB - archivo de base de datos de certificado de cliente key3.db de Netscape</li>
      <li>CERT_NICKNAME - "nickname" del certificado de cliente (SDK de Netscape)</li>
      <li>CERT_PFX - certificado de cliente codificado en PKCS#12</li>
      <li>KEY_DER - clave privada binaria codificada en DER</li>
      <li>KEY_BASE64 - clave privada codificada en PEM</li>
      <li>KEY_PFX - clave privada codificada en PKCS#12</li>
    </ul>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPTrustedClientCert</name>
<description>Establece el archivo que contiene, o el nickname que hace referencia a, un
certificado de cliente por conexión. No todos los toolkits LDAP soportan certificados
de cliente por conexión.</description>
<syntax>LDAPTrustedClientCert <var>type</var> <var>directory-path/filename/nickname</var> <var>[password]</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>
    <p>Especifica la ruta, el nombre de archivo o el nickname de un
    certificado de cliente por conexión usado al establecer una conexión SSL
    o TLS a un servidor LDAP. Distintas ubicaciones o
    directorios pueden tener su propia configuración de certificado de cliente
    independiente. Algunos toolkits LDAP (en particular Novell)
    no soportan certificados de cliente por conexión, y lanzarán un
    error al conectar con el servidor LDAP si intenta usar esta directiva
    (use en su lugar la directiva <directive module="mod_ldap">LDAPTrustedGlobalCert</directive>
    para certificados de cliente de Novell; consulte la guía de certificados SSL/TLS anterior para más detalles).
    El tipo especifica la clase de parámetro de certificado que se está
    estableciendo, dependiendo del toolkit LDAP usado. Los tipos soportados son:</p>
    <ul>
      <li>CA_DER - certificado de CA binario codificado en DER</li>
      <li>CA_BASE64 - certificado de CA codificado en PEM</li>
      <li>CERT_DER - certificado de cliente binario codificado en DER</li>
      <li>CERT_BASE64 - certificado de cliente codificado en PEM</li>
      <li>CERT_NICKNAME - "nickname" del certificado de cliente (SDK de Netscape)</li>
      <li>KEY_DER - clave privada binaria codificada en DER</li>
      <li>KEY_BASE64 - clave privada codificada en PEM</li>
    </ul>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPTrustedMode</name>
<description>Especifica el modo SSL/TLS a usar al conectar con un servidor LDAP.</description>
<syntax>LDAPTrustedMode <var>type</var></syntax>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>Se soportan los siguientes modos:</p>
    <ul>
      <li>NONE - sin cifrado</li>
      <li>SSL - cifrado ldaps:// en el puerto por defecto 636</li>
      <li>TLS - cifrado STARTTLS en el puerto por defecto 389</li>
    </ul>

    <p>No todos los toolkits LDAP soportan todos los modos anteriores. Se registrará
    un mensaje de error en tiempo de ejecución si un modo no está soportado, y la
    conexión con el servidor LDAP fallará.
    </p>

    <p>Si se especifica una URL ldaps://, el modo pasa a ser SSL y el ajuste
    de <directive>LDAPTrustedMode</directive> se ignora.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPConnectionTimeout</name>
<description>Especifica el tiempo de espera de la conexión del socket, en segundos</description>
<syntax>LDAPConnectionTimeout <var>seconds</var></syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Esta directiva configura la opción LDAP_OPT_NETWORK_TIMEOUT (o LDAP_OPT_CONNECT_TIMEOUT)
    en la biblioteca cliente LDAP subyacente, cuando está disponible. Este valor
    normalmente controla cuánto tiempo esperará la biblioteca cliente LDAP a que se complete la
    conexión TCP con el servidor LDAP.</p>

    <p> Si una conexión no tiene éxito dentro del periodo de tiempo de espera, se devolverá
    un error, o la biblioteca cliente LDAP intentará conectarse a un servidor LDAP
    secundario si se ha especificado uno (mediante una lista de nombres de host separados por
    espacios en <directive module="mod_authnz_ldap">AuthLDAPURL</directive>).</p>

    <p>El valor por defecto es 10 segundos, si la biblioteca cliente LDAP enlazada con el
    servidor soporta la opción LDAP_OPT_NETWORK_TIMEOUT.</p>

    <note>LDAPConnectionTimeout solo está disponible cuando la biblioteca cliente LDAP enlazada
    con el servidor soporta la opción LDAP_OPT_NETWORK_TIMEOUT
    (o LDAP_OPT_CONNECT_TIMEOUT), y el comportamiento final está
    dictado enteramente por la biblioteca cliente LDAP.
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>LDAPTimeout</name>
<description>Especifica el tiempo de espera para las operaciones de búsqueda y vinculación LDAP, en segundos</description>
<syntax>LDAPTimeout <var>seconds</var></syntax>
<default>LDAPTimeout 60</default>
<contextlist><context>server config</context></contextlist>
<compatibility>Apache HTTP Server 2.3.5 y posteriores</compatibility>

<usage>
    <p>Esta directiva configura el tiempo de espera para las operaciones de vinculación y búsqueda, así como
    la opción LDAP_OPT_TIMEOUT en la biblioteca cliente LDAP subyacente, cuando esté disponible.</p>

    <p> Si el tiempo de espera expira, httpd reintentará por si un firewall hubiera
    descartado silenciosamente una conexión existente. No obstante, el rendimiento será mucho mejor si
    el firewall está configurado para enviar paquetes TCP RST en lugar de descartar
    paquetes silenciosamente.</p>

    <note>
    <p>Los tiempos de espera para las operaciones de comparación LDAP requieren un SDK con LDAP_OPT_TIMEOUT, como OpenLDAP &gt;= 2.4.4.</p>
    </note>

</usage>
</directivesynopsis>


<directivesynopsis>
<name>LDAPVerifyServerCert</name>
<description>Fuerza la verificación del certificado del servidor</description>
<syntax>LDAPVerifyServerCert On|Off</syntax>
<default>LDAPVerifyServerCert On</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Especifica si se debe forzar la verificación de un
    certificado del servidor al establecer una conexión SSL al
    servidor LDAP.</p>
</usage>
</directivesynopsis>


<directivesynopsis>
<name>LDAPConnectionPoolTTL</name>
<description>Descarta las conexiones de backend que han permanecido en el pool de conexiones demasiado tiempo</description>
<syntax>LDAPConnectionPoolTTL <var>n</var></syntax>
<default>LDAPConnectionPoolTTL -1</default>
<contextlist><context>server config</context><context>virtual host</context></contextlist>
<compatibility>Apache HTTP Server 2.3.12 y posteriores</compatibility>

<usage>
    <p>Especifica la antigüedad máxima, en segundos, que una conexión LDAP en el pool puede permanecer inactiva
    y seguir estando disponible para su uso. Las conexiones se depuran cuando se necesitan de nuevo,
    no de forma asíncrona.</p>

    <p>Un valor de 0 hace que las conexiones nunca se guarden en el pool de
    conexiones de backend. El valor por defecto de -1, y cualquier otro valor negativo,
    permite reutilizar conexiones de cualquier antigüedad.</p>

    <p>Por motivos de rendimiento, el tiempo de referencia usado por esta directiva se
    basa en el momento en que la conexión LDAP se devuelve al pool, no en el momento
    de la última operación de E/S exitosa con el servidor LDAP.  </p>

    <p>Desde la versión 2.4.10, se han puesto en marcha nuevas medidas para evitar que el tiempo
    de referencia se infle por aciertos de caché o peticiones lentas. En primer lugar, el tiempo
    de referencia no se actualiza si no se necesitó ninguna conexión LDAP de backend. En segundo lugar,
    el tiempo de referencia usa el momento en que se recibió la petición HTTP en lugar
    del momento en que se completa la petición.</p>

    <note><p>Este tiempo de espera usa por defecto segundos como unidad, pero acepta
    sufijos para milisegundos (ms), minutos (min) y horas (h).
    </p></note>
</usage>
</directivesynopsis>


<directivesynopsis>
<name>LDAPLibraryDebug</name>
<description>Activa la depuración en el SDK de LDAP</description>
<syntax>LDAPLibraryDebug <var>7</var></syntax>
<default>desactivado</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Activa opciones de depuración LDAP específicas del SDK que generalmente hacen que el SDK
    de LDAP registre información de traza detallada en el log de errores principal de Apache.
    Los mensajes de traza del SDK de LDAP proporcionan detalles exhaustivos que
    pueden ser útiles al depurar problemas de conectividad con los servidores LDAP de backend</p>

    <p>Esta opción solo se puede configurar cuando Apache HTTP Server está enlazado con
    un SDK de LDAP que implemente <code>LDAP_OPT_DEBUG</code> o
    <code>LDAP_OPT_DEBUG_LEVEL</code>, como OpenLDAP (un valor de 7 es detallado)
    o Tivoli Directory Server (un valor de 65535 es detallado).</p>

    <note type="warning">
    <p>Es probable que la información registrada contenga credenciales en texto plano usadas o
    validadas por la autenticación LDAP, por lo que se debe tener cuidado al proteger y purgar
    el log de errores cuando se usa esta directiva.</p>
    </note>

</usage>
</directivesynopsis>


</modulesynopsis>
