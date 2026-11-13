<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933180 -->
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

<modulesynopsis metafile="mod_authn_socache.xml.meta">

<name>mod_authn_socache</name>
<description>Gestiona una caché de credenciales de autenticación para
reducir la carga sobre los backends</description>
<status>Base</status>
<sourcefile>mod_authn_socache.c</sourcefile>
<identifier>authn_socache_module</identifier>
<compatibility>Versión 2.3 y posteriores</compatibility>

<summary>
    <p>Mantiene una caché de credenciales de autenticación, de modo que no
    es necesaria una nueva consulta al backend para cada petición
    autenticada.</p>
</summary>

<section id="intro"><title>Caché de autenticación</title>
    <p>Algunos usuarios de métodos de autenticación más pesados, como las
    consultas a bases de datos SQL (<module>mod_authn_dbd</module>), han
    informado de que esto supone una carga inaceptable para su proveedor de
    autenticación. Un caso típico es aquel en el que una página HTML
    contiene cientos de objetos (imágenes, scripts, hojas de estilo,
    medios, etc.), y una petición a la página genera cientos de peticiones
    prácticamente inmediatas de contenido adicional autenticado.</p>
    <p><module>mod_authn_socache</module> ofrece una solución a este
    problema manteniendo una caché de credenciales de autenticación.</p>
</section>

<section id="usage"><title>Uso</title>
    <p>La caché de autenticación debería usarse cuando las consultas de
    autenticación imponen una carga significativa sobre el servidor, un
    backend o la red. Es poco probable que la autenticación por archivo
    (<module>mod_authn_file</module>) o por dbm
    (<module>mod_authn_dbm</module>) se beneficien, ya que estos métodos
    son por sí mismos rápidos y ligeros (aunque en algunos casos, como un
    archivo montado en red, el uso de caché puede merecer la pena). Otros
    proveedores, como la autenticación basada en SQL o LDAP, es más
    probable que se beneficien, en particular cuando se observa un
    problema de rendimiento. Entre los módulos estándar, <module
    >mod_authnz_ldap</module> gestiona su propia caché, así que
    normalmente solo <module>mod_authn_dbd</module> se beneficiará de esta
    caché.</p>
    <p>Las reglas básicas para habilitar la caché para un proveedor son:</p>
    <ol><li>Incluir el proveedor para el que está habilitando la caché en
            una directiva <directive module="mod_authn_socache"
            >AuthnCacheProvideFor</directive>.</li>
        <li>Listar <var>socache</var> antes del proveedor para el que
            está habilitando la caché en su directiva <directive
            module="mod_auth_basic">AuthBasicProvider</directive> o
            <directive module="mod_auth_digest"
            >AuthDigestProvider</directive>.</li>
    </ol>
    <p>Un ejemplo sencillo de uso para acelerar
    <module>mod_authn_dbd</module> usando dbm como motor de caché:</p>
    <highlight language="config">
#AuthnCacheSOCache es opcional. Si se especifica, se aplica a todo el servidor
AuthnCacheSOCache dbm
&lt;Directory "/usr/www/myhost/private"&gt;
    AuthType Basic
    AuthName "Cached Authentication Example"
    AuthBasicProvider socache dbd
    AuthDBDUserPWQuery "SELECT password FROM authn WHERE user = %s"
    AuthnCacheProvideFor dbd
    Require valid-user
    #Opcional
    AuthnCacheContext dbd-authn-example
&lt;/Directory&gt;
    </highlight>
</section>

<section id="dev"><title>Uso de caché con módulos personalizados</title>
    <p>Los desarrolladores de módulos deben tener en cuenta que sus
    módulos deben habilitarse para el uso de caché con
    <module>mod_authn_socache</module>. Se proporciona una única función
    opcional de la API, <var>ap_authn_cache_store</var>, para cachear las
    credenciales que un proveedor acaba de consultar o generar. Hay
    ejemplos de uso disponibles en <a
    href="http://svn.eu.apache.org/viewvc?view=revision&amp;revision=957072"
    >r957072</a>, en el que se habilitan tres proveedores de authn para el
    uso de caché.</p>
</section>

<directivesynopsis>
<name>AuthnCacheEnable</name>
<description>Habilita la caché de Authn configurada en cualquier lugar</description>
<syntax>AuthnCacheEnable</syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Esta directiva normalmente no es necesaria: se implica si la caché
    de autenticación está habilitada en cualquier parte de
    <var>httpd.conf</var>. Sin embargo, si no está habilitada en ninguna
    parte de <var>httpd.conf</var>, por defecto no se inicializará, y por
    lo tanto no estará disponible en un contexto <var>.htaccess</var>.
    Esta directiva asegura que se inicialice, de modo que pueda usarse en
    <var>.htaccess</var>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthnCacheSOCache</name>
<description>Selecciona el proveedor de backend socache a usar</description>
<syntax>AuthnCacheSOCache <var>provider-name[:provider-args]</var></syntax>
<contextlist><context>server config</context></contextlist>
<compatibility>Los argumentos opcionales del proveedor están disponibles
en Apache HTTP Server 2.4.7 y posteriores</compatibility>

<usage>
    <p>Esta es una configuración a nivel de todo el servidor para
    seleccionar un proveedor para la <a href="../socache.html">caché de
    objetos compartida</a>, seguida de los argumentos opcionales para ese
    proveedor. Algunos valores posibles para <var>provider-name</var> son
    "dbm", "dc", "memcache" o "shmcb", cada uno sujeto a que el módulo
    correspondiente esté cargado. Si no se establece, se usará el valor
    por defecto de su plataforma.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthnCacheProvideFor</name>
<description>Especifica para qué proveedor(es) de authn se debe usar la caché</description>
<syntax>AuthnCacheProvideFor <var>authn-provider</var> [...]</syntax>
<default>None</default>
<contextlist><context>directory</context><context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>
    <p>Esta directiva especifica uno o varios proveedores de autenticación
    para los que se debe usar la caché. Las credenciales encontradas por
    un proveedor que no esté listado en una directiva
    <directive>AuthnCacheProvideFor</directive> no se cachearán.</p>

    <p>Por ejemplo, para cachear las credenciales encontradas por
    <module>mod_authn_dbd</module> o por un proveedor personalizado
    <var>myprovider</var>, pero dejando sin cachear las consultadas por
    proveedores ligeros como file o dbm:</p>
    <highlight language="config">
AuthnCacheProvideFor dbd myprovider
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthnCacheTimeout</name>
<description>Establece un tiempo de expiración para las entradas de la caché</description>
<syntax>AuthnCacheTimeout <var>timeout</var> (seconds)</syntax>
<default>AuthnCacheTimeout 300 (5 minutos)</default>
<contextlist><context>directory</context><context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>
    <p>Cachear datos de autenticación puede suponer un problema de
    seguridad, aunque es poco probable que el uso de caché a corto plazo
    lo sea. Normalmente, una buena solución es cachear las credenciales
    durante el tiempo necesario para reducir la carga sobre un backend,
    pero no más, aunque si los cambios en sus usuarios y contraseñas son
    poco frecuentes, un tiempo de expiración más largo puede resultarle
    adecuado. El valor por defecto de 300 segundos (5 minutos) es a la vez
    prudente y suficiente para mantener baja la carga sobre un backend
    como dbd (consultas a bases de datos SQL).</p>
    <p>Esto no debe confundirse con el tiempo de expiración de la sesión,
    que es un asunto completamente diferente. Sin embargo, quizá quiera
    comprobar si su software de gestión de sesiones permite que las
    credenciales cacheadas extiendan "accidentalmente" una sesión, y
    tenerlo en cuenta al establecer su tiempo de expiración.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthnCacheContext</name>
<description>Especifica una cadena de contexto para usar en la clave de caché</description>
<syntax>AuthnCacheContext directory|server|<var>custom-string</var></syntax>
<default>AuthnCacheContext directory</default>
<contextlist><context>directory</context></contextlist>

<usage>
    <p>Esta directiva especifica una cadena que se usará junto con el
    nombre de usuario proporcionado (y el realm, en el caso de la
    autenticación Digest) para construir una clave de caché. Esto sirve
    para distinguir nombres de usuario idénticos que sirven áreas de
    autenticación diferentes en el servidor.</p>
    <p>Hay dos valores especiales para esto: <code>directory</code>, que
    usa como cadena el contexto de directorio de la petición, y
    <code>server</code>, que usa el nombre del host virtual.</p>
    <p>El valor por defecto es <code>directory</code>, que es también la
    configuración más conservadora. Esto probablemente no sea óptimo, ya
    que (por ejemplo) hace que <var>$app-base</var>,
    <var>$app-base/images</var>, <var>$app-base/scripts</var> y
    <var>$app-base/media</var> tengan cada uno su propia clave de caché
    independiente. Una política mejor es nombrar la
    <directive>AuthnCacheContext</directive> según el proveedor de
    contraseñas: por ejemplo, un archivo <var>htpasswd</var> o una tabla
    de base de datos.</p>
    <p>Los contextos pueden compartirse entre distintas áreas de un
    servidor, cuando las credenciales son compartidas. Sin embargo, esto
    tiene el potencial de convertirse en un vector para brechas de
    seguridad entre sitios o entre aplicaciones, por lo que esta directiva
    no está permitida en contextos <var>.htaccess</var>.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
