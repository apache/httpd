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

<modulesynopsis metafile="mod_md.xml.meta">

    <name>mod_md</name>
    <description>Gestión de dominios entre servidores virtuales, aprovisionamiento de certificados
        mediante el protocolo ACME
    </description>
    <status>Experimental</status>
    <sourcefile>mod_md.c</sourcefile>
    <identifier>md_module</identifier>
    <compatibility>Disponible en la versión 2.4.30 y posteriores</compatibility>
    <summary>
        <p>
        Este módulo gestiona las propiedades comunes de los dominios para uno o más servidores virtuales.
        Tiene dos propósitos principales: por un lado, supervisar/renovar los certificados TLS mediante el
        protocolo ACME (<rfc>8555</rfc>).
        Los certificados se renovarán mediante el módulo antes de su expiración, para tener en cuenta
        posibles interrupciones en los servicios de internet. Hay formas de supervisar el estado de todos
        los certificados administrados de esta manera, así como configuraciones que ejecutarán sus
        propios comandos de notificación ante renovaciones, expiraciones y errores.
        </p><p>
        En segundo lugar, mod_md ofrece una implementación alternativa de OCSP Stapling. Esto funciona
        tanto con certificados administrados como con certificados que usted mismo configure. OCSP
        Stapling es un componente necesario para cualquier sitio https:, ya que influye en los tiempos
        de carga de la página y, según otras configuraciones, en la disponibilidad de la página. Más
        información en la sección de stapling, más abajo.
        </p><p>
        La Autoridad ACME por defecto para la gestión de certificados es
        <a href="https://letsencrypt.org/">Let's Encrypt</a>, pero es posible
        configurar otra CA que soporte el protocolo.
        </p>

        <p>Ejemplo de configuración sencilla:</p>

        <note><title>TLS en un contexto de VirtualHost</title>
        <highlight language="config">
MDomain example.org

&lt;VirtualHost *:443&gt;
    ServerName example.org
    DocumentRoot htdocs/a

    SSLEngine on
    # no certificates specification
&lt;/VirtualHost&gt;
        </highlight>
        <p>
            Esta configuración hará que, al arrancar el servidor, se contacte con
            <a href="https://letsencrypt.org/">Let's Encrypt</a>
            para solicitar un certificado para el dominio. Si Let's Encrypt puede verificar la propiedad
            del dominio, el módulo obtendrá el certificado y su cadena, los almacenará
            en el sistema de archivos local (véase <directive module="mod_md">MDStoreDir</directive>)
            y los proporcionará, en el siguiente reinicio, a <module>mod_ssl</module>.
        </p><p>
            Esto ocurre mientras el servidor ya está en ejecución. Todos los demás hosts seguirán
            funcionando como antes. Mientras no haya un certificado disponible, las peticiones para el
            dominio administrado se responderán con un '503 Service Unavailable'.
        </p>
        </note>

        <note><title>Prerrequisitos</title>
        <p>
            Este módulo requiere que también esté cargado <module>mod_watchdog</module>.
        </p><p>
            El registro y la renovación de certificados con Let's Encrypt requiere que su servidor sea
            alcanzable en el puerto 80 (http:) y/o en el puerto 443 (https:) desde internet público.
            (A menos que su servidor esté configurado para usar DNS para los desafíos; más sobre eso
             en 'certificados wildcard')
        </p><p>
            El módulo seleccionará entre los métodos que ofrece Let's Encrypt. Normalmente, LE ofrece
            desafíos tanto en ambos puertos como en DNS, y Apache elige un método disponible.
        </p><p>
            Para determinar cuál está disponible, el módulo examina los puertos en los que
            escucha Apache httpd. Si estos incluyen el puerto 80, asume que el
            desafío http: (llamado http-01) está disponible. Si el servidor escucha
            en el puerto 443, también se añade a la lista el desafío https: (llamado tls-alpn-01).
            (Y si <directive module="mod_md">MDChallengeDns01</directive>
            está configurado, también se añade el desafío dns-01.)
        </p><p>
            Si su configuración no es tan sencilla, hay dos métodos disponibles
            para influir en esto. Primero, consulte <directive module="mod_md">MDPortMap</directive>
            si el servidor está detrás de un mapeador de puertos, como un cortafuegos. Segundo, puede
            anular por completo la deducción del módulo configurando directamente
            <directive module="mod_md">MDCAChallenges</directive>.
        </p>
        </note>

        <note><title>Desafíos https:</title>
        <p>
            Para la verificación de dominio mediante el protocolo TLS, `tls-alpn-01` es el nombre
            de este tipo de desafío. Requiere que el servidor Apache escuche en el puerto 443
            (véase <directive module="mod_md">MDPortMap</directive> si asigna ese puerto
            a otro distinto).
        </p><p>
            Let's Encrypt abrirá una conexión TLS con Apache usando el indicador especial
            `acme-tls/1` (esta parte de indicación de TLS se llama ALPN, de ahí el nombre
            del desafío. ALPN también lo usan los navegadores para solicitar una conexión HTTP/2).
        </p><p>
            Igual que con el protocolo HTTP/2, para permitir esto, configure:
        </p>
        <highlight language="config">
Protocols h2 http/1.1 acme-tls/1
        </highlight>
        <p>
            Y el tipo de desafío `tls-alpn-01` quedará disponible.
        </p>
        </note>

        <note><title>Certificados Wildcard</title>
        <p>
            Los certificados wildcard son posibles, pero no es inmediato usarlos tal cual,
            de forma directa. Let's Encrypt requiere la verificación mediante el desafío
            `dns-01` para estos. Ningún otro se considera lo bastante válido.
        </p><p>
            La dificultad aquí es que Apache no puede hacer esto por sí solo. Como su nombre indica, `dns-01`
            requiere que usted muestre determinados registros DNS específicos de su dominio que contengan
            cierta información de desafío. Así que necesita _escribir_ los registros DNS de su dominio.
        </p><p>
            Si sabe cómo hacerlo, puede integrarlo con mod_md. Supongamos
            que tiene un script para ello en `/usr/bin/acme-setup-dns`; configure
            Apache con:
        </p>
        <highlight language="config">
MDChallengeDns01 /usr/bin/acme-setup-dns
        </highlight>
        <p>
            y Apache llamará a este script cuando necesite configurar/eliminar un registro de desafío DNS
            para un dominio.
        </p><p>
            Suponiendo que quiere un certificado para `*.mydomain.com`, mod_md llamará a:
        </p>
        <highlight language="config">
/usr/bin/acme-setup-dns setup mydomain.com challenge-data
# this needs to remove all existing DNS TXT records for
# _acme-challenge.mydomain.com and create a new one with
# content "challenge-data"
        </highlight>
        <p>
            y después llamará a
        </p>
        <highlight language="config">
/usr/bin/acme-setup-dns teardown mydomain.com
# this needs to remove all existing DNS TXT records for
# _acme-challenge.mydomain.com
        </highlight>
        </note>

        <note><title>Monitorización</title>
            <p>
                Apache dispone de un módulo estándar de monitorización: <module>mod_status</module>.
                mod_md aporta una sección y facilita la monitorización
                de sus dominios.
            </p><p>
                Verá todos sus MD listados alfabéticamente, los nombres de dominio que contienen,
                un estado general, los tiempos de expiración y la configuración específica. La configuración
                muestra su selección de tiempos de renovación (o el valor por defecto), la CA que se usa,
                etc.
            </p><p>
                La columna 'Renewal' mostrará la actividad y las descripciones de error de las renovaciones
                de certificados. Esto debería facilitar que la gente averigüe si todo
                va bien o qué ha fallado.
            </p><p>
                Si hay un error con un MD, también se mostrará aquí. Esto le permite
                evaluar los problemas sin tener que rebuscar en los registros (logs) de su servidor.
            </p><p>
                También hay disponible un nuevo manejador '<code>md-status</code>' que le ofrece la información de los MD
                desde '<code>server-status</code>' en formato JSON. Se configura como
            </p>
            <highlight language="config">
&lt;Location "/md-status">
  SetHandler md-status
  Require host example.com
&lt;/Location>
            </highlight>
            <p>
                en su servidor. Igual que con '<code>server-status</code>', <strong>debe</strong> proteger
                la salida de <code>md-status</code> frente a la vista pública usando restricciones de autorización (como <module>mod_authz_host</module>).
            </p><p>
                Si simplemente quiere comprobar el estado JSON de un dominio específico, basta con añadir
                ese dominio a su url de estado:
            </p>
            <highlight language="config">
> curl https://&lt;yourhost>/md-status/another-domain.org
{
  "name": "another-domain.org",
  "domains": [
    "another-domain.org",
    "www.another-domain.org"
  ],
  ...
            </highlight>
            <p>
                Este estado JSON también muestra un registro de actividades cuando se renuevan dominios:
            </p>
            <highlight language="config">
{
"when": "Wed, 19 Jun 2019 14:45:58 GMT",
"type": "progress", "detail": "The certificate for the managed domain has been renewed successfully and can be used. A graceful server restart now is recommended."
},{
"when": "Wed, 19 Jun 2019 14:45:58 GMT",
"type": "progress", "detail": "Retrieving certificate chain for test-901-003-1560955549.org"
},{
"when": "Wed, 19 Jun 2019 14:45:58 GMT",
"type": "progress", "detail": "Waiting for finalized order to become valid"
},{
"when": "Wed, 19 Jun 2019 14:45:50 GMT",
"type": "progress", "detail": "Submitting CSR to CA for test-901-003-1560955549.org"
},
...
            </highlight>
            <p>
                También encontrará esta información en el archivo `job.json` de su directorio de staging y,
                cuando esté activado, en el de dominios. Esto le permite inspeccionarlos en
                cualquier momento posterior.
            </p><p>
                Además, está <directive module="mod_md">MDCertificateStatus</directive>, que
                da acceso a la información relevante del certificado en formato JSON.
            </p>
        </note>

        <note><title>Stapling</title>
            <p>
                Si quiere probar primero el stapling en un único Dominio Administrado,
                configure:
            </p>
            <highlight language="config">
&lt;MDomain mydomain.net>
  MDStapling on
&lt;/MDomain>
            </highlight>
            <p>
                y use '<code>server-status</code>' y/o <directive module="mod_md">MDMessageCmd</directive> para ver cómo funciona. Verá
                si hay información de Stapling disponible, cuánto tiempo es válida, de dónde proviene y
                cuándo se actualizará.
            </p><p>
                Si todo esto funciona a su entera satisfacción, puede activarlo para todos sus
                certificados o solo para los administrados.
            </p><p>
                La implementación de stapling de mod_ssl la usan muchos sitios
                desde hace años. Hay dos diferencias principales entre la de mod_ssl y la
                de mod_md:
            </p>
            <ol>
                <li>Por demanda frente a programado: mod_ssl obtiene la información de stapling
                cuando se solicita, por ejemplo en una nueva conexión. mod_md la obtiene
                justo al arrancar el servidor y después de 2/3 de su vida útil.</li>
                <li>En memoria frente a persistido: mod_ssl <em>puede</em> persistir esta
                información, pero la mayoría de las configuraciones de ejemplo usan una caché en memoria. mod_md
                siempre la almacena en el sistema de archivos.</li>
            </ol>
            <p>
                Si tiene la mala suerte de reiniciar su servidor durante una interrupción del servicio
                OCSP de su CA, sus usuarios podrían dejar de poder acceder a sus sitios. Sin persistencia,
                su servidor no puede proporcionar los datos al cliente, y el navegador del cliente
                tampoco puede obtenerlos, ya que el servicio OCSP no está respondiendo.
            </p><p>
                La implementación de mod_md la habrá persistido, la cargará de nuevo tras el
                reinicio y la tendrá disponible para las conexiones entrantes. Uno o dos días antes
                de que esta información caduque, la renovará, lo que le permite soportar
                una interrupción prolongada del servicio OCSP.
            </p><p>
                Por motivos de compatibilidad hacia atrás, la implementación existente en mod_ssl no se
                podía cambiar de forma drástica. Por ejemplo, mod_ssl no puede añadir una dependencia
                de mod_watchdog sin romper muchas instalaciones existentes (que no lo cargan).
            </p>
        </note>

    </summary>

    <directivesynopsis>
        <name>MDomain</name>
        <description>Define la lista de nombres de dominio que pertenecen a un mismo grupo.</description>
        <syntax>MDomain <var>dns-name</var> [ <var>other-dns-name</var>... ] [auto|manual]</syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>

        <usage>
            <p>
                Todos los nombres de la lista se administran como un único Dominio Administrado (MD).
                mod_md solicitará un único certificado válido para todos esos nombres. Esta
                directiva usa la configuración global (véanse las demás directivas MD más abajo). Si
                necesita configuraciones específicas para un MD, use
                <directive module="mod_md" type="section">MDomainSet</directive>.
            </p><p>
                Hay 2 configuraciones adicionales necesarias para un Dominio Administrado:
                una dirección de correo de contacto (mediante <directive module="mod_md">MDContactEmail</directive> o <directive module="core">ServerAdmin</directive>)
                y <directive module="mod_md">MDCertificateAgreement</directive>.
                La dirección de correo de <directive module="core">ServerAdmin</directive>
                se usa para registrarse en la CA (Let's Encrypt por defecto).
                La CA puede usarla para notificarle sobre
                cambios en su servicio o en el estado de sus certificados.
            </p><p>
                La segunda configuración, <directive module="mod_md">MDCertificateAgreement</directive>,
                debe tener el valor "accepted". Al indicarlo, confirma que
                acepta los Términos del Servicio de la CA.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
MDContactEmail admin@example.org
MDCertificateAgreement accepted
MDomain example.org www.example.org

&lt;VirtualHost *:443&gt;
    ServerName example.org
    DocumentRoot htdocs/root

    SSLEngine on
&lt;/VirtualHost&gt;

&lt;VirtualHost *:443&gt;
    ServerName www.example.org
    DocumentRoot htdocs/www

    SSLEngine on
&lt;/VirtualHost&gt;
                </highlight>
            </example>
            <p>
                Hay dos nombres especiales que puede usar en esta directiva: 'manual'
                y 'auto'. Esto determina si un Dominio Administrado debe tener exactamente la
                lista de nombres tal como se configura ('manual') u ofrecer más comodidad. Con 'auto'
                se añaden al MD todos los nombres de un servidor virtual. Por comodidad, 'auto' es también
                el valor por defecto.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
MDomain example.org

&lt;VirtualHost *:443&gt;
    ServerName example.org
    ServerAlias www.example.org
    DocumentRoot htdocs/root

    SSLEngine on
&lt;/VirtualHost&gt;

MDomain example2.org auto

&lt;VirtualHost *:443&gt;
    ServerName example2.org
    ServerAlias www.example2.org
    ...
&lt;/VirtualHost&gt;
                </highlight>
            </example>
            <p>
                En este ejemplo, el dominio 'www.example.org' se añade automáticamente al
                MD 'example.org'. De forma similar para 'example2.org', donde 'auto' se configura
                explícitamente. Siempre que añada más nombres ServerAlias a este
                servidor virtual, también se añadirán al Dominio Administrado.
            </p><p>
                Si prefiere declarar explícitamente todos los nombres de dominio, use el modo 'manual'.
                Se registrará un error si los nombres no coinciden con los esperados.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis type="section" idtype="section">
        <name>MDomainSet</name>
        <description>Contenedor para directivas aplicadas a los mismos dominios administrados.</description>
        <syntax>&lt;MDomainSet <var>dns-name</var> [ <var>other-dns-name</var>... ]&gt;...&lt;/MDomainSet&gt;</syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>

        <usage>
            <p>
                Esta es la directiva <directive module="mod_md">MDomain</directive>
                con la posibilidad añadida de incluir configuración solo para este MD. De hecho,
                también puede usar "&lt;MDomain ..>" como forma abreviada.
            </p>
            <p>
                Esto le permite configurar un MD que use otra Autoridad de Certificación,
                tenga otros requisitos de renovación, etc.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
&lt;MDomain sandbox.example.org&gt;
    MDCertificateAuthority   https://someotherca.com/ACME
&lt;/MDomain&gt;
                </highlight>
            </example>
        <p>
            Un caso de uso habitual es configurar por separado los requisitos https: para
            sus dominios.
        </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
&lt;MDomain example.org&gt;
    MDRequireHttps temporary
&lt;/MDomain&gt;
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDCertificateAgreement</name>
        <description>Confirma que ha aceptado los Términos del Servicio de la Autoridad
        de Certificación.</description>
        <syntax>MDCertificateAgreement accepted</syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>Cuando usa mod_md para obtener un certificado, se convierte en cliente de la CA (p. ej. Let's Encrypt). Esto
            significa que necesita leer y aceptar sus Términos del Servicio,
            para entender qué ofrecen y qué pueden excluir o exigirle.
            mod_md no puede, por sí mismo, aceptar algo así.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDCertificateAuthority</name>
        <description>La URL(s) de la Autoridad de Certificación ACME a usar.</description>
        <syntax>MDCertificateAuthority <var>url</var></syntax>
        <default>MDCertificateAuthority letsencrypt</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                La(s) URL(s) donde la CA ofrece su servicio.
                En lugar de la URL real, puede usar 'letsencrypt' o 'buypass'.
            </p><p>
                Si configura más de una URL, cada una se prueba de forma rotatoria
                tras un número de fallos. Puede configurar con qué rapidez o
                retraso ocurre esto mediante las directivas <directive module="mod_md">MDRetryDelay</directive> y
                <directive module="mod_md">MDRetryFailover</directive>. La configuración por defecto
                realiza el cambio tras aproximadamente medio día de intentos.
            </p><p>
                El resto de configuraciones se aplican a cada una de estas URLs. Por tanto, no
                es posible tener dos con distintos
                <directive module="mod_md">MDExternalAccountBinding</directive>, por ejemplo.
            </p><p>
                Para pruebas, las CA suelen ofrecer una segunda URL de servicio.
                El servicio de 'prueba' no proporciona certificados válidos en un navegador,
                pero es más permisivo respecto a los límites de tasa.
                Esto permite verificar su propia configuración antes de cambiar
                a la URL de servicio de producción.
            </p>
            <example><title>Configuración de Pruebas de LE</title>
                <highlight language="config">
MDCertificateAuthority https://acme-staging-v02.api.letsencrypt.org/directory
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDCertificateProtocol</name>
        <description>El protocolo a usar con la Autoridad de Certificación.</description>
        <syntax>MDCertificateProtocol <var>protocol</var></syntax>
        <default>MDCertificateProtocol ACME</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Especifica el protocolo a usar. Actualmente, solo se soporta <code>ACME</code>.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDDriveMode</name>
        <description>antiguo nombre de MDRenewMode.</description>
        <syntax>MDDriveMode always|auto|manual</syntax>
        <default>MDDriveMode auto</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>Esta directiva existe por compatibilidad hacia atrás, como el antiguo nombre de
            <directive module="mod_md">MDRenewMode</directive>.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDRenewMode</name>
        <description>Controla si los certificados deben renovarse.</description>
        <syntax>MDRenewMode always|auto|manual</syntax>
        <default>MDRenewMode auto</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                En el modo 'auto' por defecto, el módulo hará lo que tenga más sentido
                para cada Dominio Administrado. Para un dominio sin ningún certificado, los
                obtendrá de la Autoridad de Certificación.
            </p>
            <p>
                Sin embargo, si ha definido un MD que no usa ningún VirtualHost de
                Apache, no se molestará. Y para los MD con archivos de certificado estáticos
                (véase <directive module="mod_md">MDCertificateFile</directive>),
                asume que tiene su propia fuente, y tampoco los renovará.
            </p>
            <p>
                Puede anular este comportamiento por defecto en cualquiera de los dos sentidos. Si especifica 'always',
                el módulo renovará los certificados de un MD, sin importar si los
                dominios están en uso o si hay archivos estáticos.
            </p>
            <p>
                Para el efecto contrario, configure 'manual' y no se intentará
                ninguna renovación.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDHttpProxy</name>
        <description>Define un proxy para las conexiones salientes.</description>
        <syntax>MDHttpProxy <var>url</var></syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Desde la versión 2.4.69, se puede configurar un proxy por separado para cada MDomain.</compatibility>
        <usage>
            <p>
                Use la URL del proxy de reenvío http indicada para conectar con la <directive module="mod_md">MDCertificateAuthority</directive>.
                Defina esto si su servidor web solo puede alcanzar internet mediante un proxy de reenvío.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDHttpProxyCACertificateFile</name>
        <description>Establece los certificados raíz (CA) a usar para las conexiones TLS con el proxy http.</description>
        <syntax>MDHttpProxyCACertificateFile <var>path-to-pem-file</var></syntax>
        <default>MDHttpProxyCACertificateFile none</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.69 y posteriores</compatibility>
        <usage>
            <p>
                Esto se usa para las conexiones al proxy de reenvío HTTPS (<directive module="mod_md">MDHttpProxy</directive>).
                Es necesario si el certificado del proxy HTTPS no se puede verificar usando el almacén general de CA raíz.
                Esto ocurre a veces en configuraciones de pruebas o en entornos corporativos.
            </p>
            <p>
                El certificado del servidor ACME se verifica con los certificados raíz establecidos mediante
                <directive module="mod_md">MDCACertificateFile</directive>, por lo que puede necesitar ambas configuraciones.
            </p>
            <p>
                Use "none" como ruta para desactivarlo explícitamente.
            </p>
            <p>
                Esto se puede configurar por separado para cada <directive module="mod_md">MDomain</directive>.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDMember</name>
        <description>Nombre de host adicional para el dominio administrado.</description>
        <syntax>MDMember <var>hostname</var></syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
            En lugar de indicar todos los nombres dns en la misma línea, puede usar
            <directive>MDMember</directive> para añadir esos nombres
            a un dominio administrado.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
&lt;MDomain example.org&gt;
    MDMember www.example.org
    MDMember mail.example.org
&lt;/MDomain&gt;
                </highlight>
            </example>
            <p>
               Si la usa en el contexto global, fuera de un MD concreto, solo puede
               especificar un valor, 'auto' o 'manual', como valor por defecto para el resto de MD. Véase
               <directive module="mod_md">MDomain</directive> para una
               descripción de estos valores especiales.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDMembers</name>
        <description>Controla si los nombres de dominio alias se añaden automáticamente.</description>
        <syntax>MDMembers auto|manual</syntax>
        <default>MDMembers auto</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>Define si los valores <directive module="core">ServerName</directive> y
               <directive module="core">ServerAlias</directive> de un VirtualHost
               se añaden automáticamente a los miembros de un Dominio Administrado o no.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDMustStaple</name>
        <description>Controla si los nuevos certificados llevan la marca OCSP Must Staple.</description>
        <syntax>MDMustStaple on|off</syntax>
        <default>MDMustStaple off</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>Define si los certificados recién solicitados deben tener activada la marca
            OCSP Must Staple o no. Si un certificado tiene esta marca, el servidor está obligado a enviar una
            respuesta de OCSP stapling a cada cliente. Esto solo funciona si configura
            <module>mod_ssl</module> para generarla (véase <directive module="mod_ssl">SSLUseStapling</directive>
            y directivas relacionadas).
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDNotifyCmd</name>
        <description>Ejecuta un programa cuando un Dominio Administrado está listo.</description>
        <syntax>MDNotifyCmd <var>path</var> [ <var>args</var> ]</syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                El ejecutable configurado se ejecuta cuando un Dominio Administrado se ha registrado o
                ha renovado su certificado. Se le pasa el nombre del MD procesado como
                argumento adicional (después de los parámetros especificados aquí). Debería
                devolver el código de estado 0 para indicar que se ha ejecutado correctamente.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDPortMap</name>
        <description>Asigna puertos externos a internos para la verificación de propiedad de dominios.</description>
        <syntax>MDPortMap <var>map1</var> [ <var>map2</var> ]</syntax>
        <default>MDPortMap http:80 https:443</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                El protocolo ACME ofrece dos métodos para verificar la propiedad de un dominio mediante
                HTTP: uno que usa urls 'http:' (puerto 80) y otro para urls 'https:'
                (puerto 443). Si su servidor no es alcanzable por al menos uno
                de los dos, ACME solo puede funcionar configurando su servidor DNS,
                véase <directive module="mod_md">MDChallengeDns01</directive>.
            </p><p>
                En la mayoría de los servidores de cara al público, 'http:' llega por el puerto 80 y
                'https:' por el puerto 443. El módulo comprueba los puertos en los que su servidor
                Apache está escuchando y asume que esos están disponibles. Esto significa que,
                cuando su servidor no escucha en el puerto 80, asume que
                las peticiones 'http:' desde internet no funcionarán.
            </p><p>
                Es una suposición razonable, pero puede ser errónea. Por ejemplo, su Apache
                podría escuchar en el puerto 80, pero su cortafuegos podría bloquearlo. 'http:'
                solo está disponible en su intranet. Entonces, el módulo asumirá erróneamente
                que Let's Encrypt puede usar desafíos 'http:' con su servidor. Esto
                fallará, porque su cortafuegos los descartará.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
MDPortMap http:- https:8433
                </highlight>
            </example>
            <p>
                El ejemplo anterior muestra cómo puede especificar que las peticiones 'http:' desde
                internet nunca llegarán. Además, indica que las peticiones 'https:'
                llegarán por el puerto local 8433.
            </p><p>
                Esto es necesario si tiene redirección de puertos configurada; su servidor puede ser
                alcanzable desde Internet por el puerto 443, pero el puerto local que usa httpd es
                otro distinto. Su servidor podría escuchar solo en los puertos 8443 y 8000, pero ser alcanzado
                en los puertos 443 y 80 (desde internet).
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDPrivateKeys</name>
        <description>Establece el tipo y el tamaño de las claves privadas generadas.</description>
        <syntax>MDPrivateKeys <var>type</var> [ <var>params</var>... ]</syntax>
        <default>MDPrivateKeys RSA 2048</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Define qué tipo de claves privadas se generan para un dominio administrado y con
                qué parámetros. Puede tener configurado más de un tipo de clave privada, y
                el módulo obtendrá un certificado para cada clave.
            </p><p>
                Por ejemplo, puede configurar una clave RSA y una de Curva Elíptica (EC), de forma
                que se creen 2 certificados para un dominio. En una conexión de cliente, se usará
                la primera que soporte el cliente.
            </p><p>
                Dado que las claves y los certificados EC son más pequeños, puede que quiera ofrecerlos
                primero a todos los clientes (modernos) compatibles. Esto puede permitir
                negociaciones más rápidas. Añada un tipo de clave RSA para dar soporte a clientes más antiguos.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
MDPrivateKeys secp256r1 rsa3072
                </highlight>
            </example>
            <p>
                Los tipos EC soportados dependen de la CA que use. Para Let's Encrypt
                las curvas soportadas incluyen 'secp256r1' y 'secp384r1'.
            </p><p>
                Cada tipo de clave y certificado se almacena en su propio archivo en el
                almacén de MD. El tipo de clave forma parte del nombre del archivo, con cierta
                compatibilidad hacia atrás en la nomenclatura para los certificados RSA. Así puede seguir
                compartiendo estos archivos con otras aplicaciones.
            </p><p>
                Tenga en cuenta que esta configuración solo afecta a las claves nuevas. Cualquier
                clave privada existente permanece sin cambios. Además, esto solo afecta a las claves privadas
                generadas para certificados. Las claves de cuenta ACME no se ven afectadas por esto.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDRenewWindow</name>
        <description>Controla cuándo se renovará un certificado.</description>
        <syntax>MDRenewWindow <var>duration</var></syntax>
        <default>MDRenewWindow 33%</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
            Si la validez del certificado cae por debajo de la duración indicada, <module>mod_md</module>
            obtendrá un nuevo certificado firmado.
            </p><p>
            Normalmente, los certificados son válidos durante unos 90 días y mod_md los renovará
            como muy pronto cuando falte un 33% de su vida útil total (es decir, para
            una validez de 90 días, 30 días antes de que caduque). Si cree que esto no es lo que
            necesita, puede especificar bien el tiempo exacto, como en:
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
# 21 days before expiry
MDRenewWindow 21d
# 30 seconds (might be close)
MDRenewWindow 30s
# 10% of the cert lifetime
MDRenewWindow 10%
                </highlight>
            </example>
            <p>En el modo de accionamiento automático, el módulo comprobará al menos cada 12 horas
            cuál es el estado de los dominios administrados y si necesita hacer algo.
            Ante errores, por ejemplo cuando la CA no está accesible, reintentará inicialmente
            tras unos segundos. Si esto sigue fallando, irá espaciando los reintentos hasta un
            intervalo máximo de comprobaciones cada hora.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDRequireHttps</name>
        <description>Redirige el tráfico http: a https: para los Dominios Administrados.</description>
        <syntax>MDRequireHttps off|temporary|permanent</syntax>
        <default>MDRequireHttps off</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>Esta es una directiva de comodidad para facilitar la migración de http: a https: de
            sus Dominios Administrados. Con:
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
MDRequireHttps temporary
                </highlight>
            </example>
            <p>indica que, por ahora, quiere que todo el tráfico mediante URLs http: se redirija
            a las URLs https: correspondientes. Esto es seguro y puede eliminarlo de nuevo en
            cualquier momento.
            </p><p>
                <strong>Lo siguiente tiene consecuencias: </strong>si quiere que los clientes dejen de usar las
             URLs http: <strong>por completo</strong>, configure:
            </p>
            <example><title>Permanente (¡durante al menos medio año!)</title>
                <highlight language="config">
MDRequireHttps permanent
                </highlight>
            </example>
            <p>Esto hace dos cosas:
            </p>
            <ol>
                <li>Todas las peticiones a los recursos <code>http:</code> se redirigen a la
                    misma url con el esquema <code>https:</code> usando el código de estado
                <code>301</code>. Esto indica a los clientes que la intención es que sea para siempre y
                que deberían actualizar sus enlaces en consecuencia.
                </li>
                <li>Todas las respuestas a peticiones <code>https:</code> llevarán la cabecera
                    <code>Strict-Transport-Security</code> con un tiempo de vida de medio año.
                    Esto indica al navegador que <strong>nunca</strong> (durante medio año) debe usar <code>http:</code>
                    al comunicarse con este nombre de dominio. Tras ver esto, los navegadores se negarán
                    a contactar con su sitio sin cifrar. Esto evita que un intermediario malicioso
                    degrade las conexiones y escuche/manipule el tráfico. Lo cual es bueno. Pero
                    no puede simplemente deshacerlo después.
                </li>
            </ol>
            <p>Puede lograr lo mismo con <module>mod_alias</module> y alguna
            configuración de <directive module="mod_alias">Redirect</directive>,
            básicamente. Si lo hace usted mismo, asegúrese de excluir las rutas
            /.well-known/* de su redirección; de lo contrario, mod_md
            podría tener problemas para firmar nuevos certificados.
            </p>
            <p>Si configura esto de forma global, se aplica a todos los dominios administrados. Si lo
            quiere solo para un dominio específico, use:
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
&lt;MDomain xxx.yyy&gt;
  MDRequireHttps temporary
&lt;/MDomain&gt;
                </highlight>
            </example>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDStoreDir</name>
        <description>Ruta en el sistema de archivos local donde almacenar los datos de los Dominios Administrados.</description>
        <syntax>MDStoreDir <var>path</var></syntax>
        <default>MDStoreDir md</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Define dónde se almacenan en el sistema de archivos local los datos del Dominio Administrado. Esta es
                una ruta absoluta o se interpreta relativa a la raíz del servidor. Por defecto se crea
                un directorio 'md' en su raíz del servidor.
            </p><p>
                Si cambia esto y ya tiene datos, asegúrese de mover/copiar primero los datos a
                la nueva ubicación, reconfigurar y después reiniciar el servidor. Si reconfigura
                y reinicia primero, el servidor intentará obtener nuevos certificados porque cree
                que faltan.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDCAChallenges</name>
        <description>Tipo de desafío ACME usado para probar la propiedad del dominio.</description>
        <syntax>MDCAChallenges <var>name</var> [ <var>name</var> ... ]</syntax>
        <default>MDCAChallenges tls-alpn-01 http-01 dns-01</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Establece los tipos de desafío (en orden de preferencia) al probar la propiedad del dominio.
                El módulo soporta los métodos de desafío 'tls-alpn-01', 'dns-01'
                y 'http-01'. El módulo examinará la configuración general del servidor
                para averiguar qué métodos se pueden usar.
            </p><p>
                Si el servidor escucha en el puerto 80, por ejemplo, el método 'http-01' está disponible.
                El requisito previo para 'dns-01' es tener configurado un comando <directive module="mod_md">MDChallengeDns01</directive>.
                'tls-alpn-01' se describe más arriba en 'Desafíos https:'.
            </p><p>
                Esta selección automática funciona en la mayoría de las configuraciones. Pero dado que Apache es un servidor
                muy potente con muchas opciones de configuración, la situación no está clara para todos
                los casos posibles. Por ejemplo: puede escuchar en varias direcciones IP, de las cuales algunas
                son alcanzables por `https:` y otras no.
            </p><p>
                Si configura <directive>MDCAChallenges</directive> directamente, esta selección automática se desactiva.
                En su lugar, el módulo usará la lista de desafíos configurada al comunicarse con
                el servidor ACME (el servidor también debe ofrecer ese tipo de desafío).
                Estos desafíos se examinan en el orden especificado.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDBaseServer</name>
        <description>Controla si el servidor base puede administrarse o solo los servidores virtuales.</description>
        <syntax>MDBaseServer on|off</syntax>
        <default>MDBaseServer off</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
            Controla si el servidor base, el que está fuera de todos los VirtualHosts, debe ser administrado por
            mod_md o no. Por defecto, no lo será. Precisamente porque
            puede tener efectos secundarios confusos. Se recomienda tener servidores virtuales
            para todos los dominios administrados y no depender de la configuración global de respaldo del servidor.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDCertificateFile</name>
        <description>Especifica un archivo de certificado estático para el MD.</description>
        <syntax>MDCertificateFile <var>path-to-pem-file</var></syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Esto se usa dentro de un <directive module="mod_md">MDomainSet</directive> y especifica
                el archivo que contiene la cadena de certificados para el Dominio Administrado. La clave
                correspondiente se especifica mediante <directive module="mod_md">MDCertificateKeyFile</directive>.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
&lt;MDomain mydomain.com>
  MDCertificateFile /etc/ssl/my.cert
  MDCertificateKeyFile /etc/ssl/my.key
&lt;/MDomain>
                </highlight>
            </example>

            <p>
                Esto es el equivalente de la directiva de mod_ssl
                <directive module="mod_ssl">SSLCertificateFile</directive>. Tiene
                varios usos.
            </p><p>
                Por un lado, si quiere migrar un dominio existente, que usa archivos estáticos, a
                certificados automatizados de Let's Encrypt. Define el
                <directive module="mod_md">MDomainSet</directive>, añade aquí los archivos y elimina
                <directive module="mod_ssl">SSLCertificateFile</directive> de
                sus VirtualHosts.
            </p><p>
                Esto le dará el mismo resultado que antes, quizá con menos líneas repetidas
                en su configuración. Después puede añadirle <directive module="mod_md">MDRenewMode</directive>
                'always', y el módulo obtendrá un nuevo certificado antes de que
                caduque el del archivo. Cuando lo haya hecho, elimine
                <directive>MDCertificateFile</directive> y recargue el servidor.
            </p><p>
                Otro caso de uso es que renueve sus certificados de Let's Encrypt con
                otro cliente ACME, por ejemplo el excelente
                <a href="https://certbot.eff.org">certbot</a>. Entonces haga que sus MD apunten
                a los archivos de certbot, de forma que ambos funcionen juntos.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDCertificateKeyFile</name>
        <description>Especifica una clave privada estática para el certificado estático.</description>
        <syntax>MDCertificateKeyFile <var>path-to-file</var></syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Esto se usa dentro de un <directive module="mod_md">MDomainSet</directive> y especifica
                el archivo que contiene la clave privada para el Dominio Administrado. El certificado
                correspondiente se especifica mediante <directive module="mod_md">MDCertificateFile</directive>.
            </p><p>
                Esto es el equivalente de la directiva de mod_ssl
                <directive module="mod_ssl">SSLCertificateKeyFile</directive>.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDCertificateStatus</name>
        <description>Expone información pública del certificado en JSON.</description>
        <syntax>MDCertificateStatus on|off</syntax>
        <default>MDCertificateStatus on</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Cuando está activada, hay disponible un recurso en los Dominios Administrados en
                'https://domain/.httpd/certificate-status' que devuelve un documento
                JSON con las propiedades clave del certificado actual y, cuando esté disponible,
                de uno renovado.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
{
  "valid-until": "Thu, 29 Aug 2019 16:06:35 GMT",
  "valid-from": "Fri, 31 May 2019 16:06:35 GMT",
  "serial": "03039C464D454EDE79FCD2CAE859F668F269",
  "sha256-fingerprint": "1ff3bfd2c7c199489ed04df6e29a9b4ea6c015fe8a1b0ce3deb88afc751e352d"
  "renewal" : { ...renewed cert information... }
}
                </highlight>
            </example>
        </usage>
    </directivesynopsis>


    <directivesynopsis>
        <name>MDChallengeDns01</name>
        <description>Establece el comando para configurar/eliminar los desafíos dns-01</description>
        <syntax>MDChallengeDns01 <var>path-to-command</var></syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Define un programa al que se llamará cuando sea necesario configurar/eliminar el desafío `dns-01`.
                Al programa se le pasa el argumento `setup` o `teardown` seguido del nombre de dominio.
                Para `setup` se añade además el contenido del desafío. Cuando
                <directive module="mod_md">MDChallengeDns01Version</directive> está establecido a 2,
                `teardown` también recibe el contenido del desafío como argumento.
            </p><p>
                No necesita especificar esto mientras sea posible algún método de desafío 'http:' o 'https:'.
                Sin embargo, Let's Encrypt hace que 'dns-01' sea el único
                desafío disponible para los certificados wildcard. Si necesita
                alguno de estos, debe configurar esto.
            </p><p>
                Ahora es posible usar esta directiva dentro de una sección <directive module="mod_md">MDomain</directive>
                para especificar un comando concreto para ese dominio. Esto permite configurar
                un script específico para el proveedor DNS en concreto implicado.
            </p><p>
                Véase la sección sobre certificados wildcard más arriba para más detalles.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDMessageCmd</name>
        <description>Gestiona eventos para los Dominios Administrados</description>
        <syntax>MDMessageCmd <var>path-to-cmd</var> <var>optional-args</var></syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Este comando se llama cuando ocurre uno de los siguientes eventos para
                un Dominio Administrado: "renewed", "installed", "expiring", "errored", "renewing", "challenge-setup:type:domain", "ocsp-renewed", "ocsp-errored". El comando podría
                invocarse para más eventos en el futuro, e ignorará los eventos
                que no esté preparado para gestionar.
            </p><p>
                Este es el compañero más flexible de <directive module="mod_md">MDNotifyCmd</directive>.
            </p>
            <example><title>Ejemplo</title>
                <highlight language="config">
MDMessageCmd /etc/apache/md-message
                </highlight>

# will be invoked when a new certificate for mydomain.org is available as:
/etc/apache/md-message renewed mydomain.com
            </example>
            <p>
                El programa no debería bloquearse, ya que el módulo esperará a que termine. Un
                código de retorno distinto de 0 se considera un error.
            </p><p>
                'errored' no es motivo inmediato de preocupación, ya que la renovación se intenta
                con suficiente antelación para permitir que internet se recupere. Esto se notifica como máximo
                una vez por hora.
            </p><p>
                'expiring' debería tomarse en serio. Se emite cuando se alcanza
                <directive module="mod_md">MDWarnWindow</directive>. Por defecto es el
                10% de la vida útil del certificado, por lo que para Let's Encrypt actualmente
                esto significa 9 días antes de que caduque. El aviso se repite como máximo
                una vez al día.
            </p><p>
                'renewed' significa que se ha obtenido un nuevo certificado y se ha almacenado
                en el área de 'staging' del almacén de MD. Se activará en el siguiente
                reinicio/recarga del servidor.
            </p><p>
                'installed' se dispara cuando un nuevo certificado se ha transferido desde
                staging a la ubicación de dominios en el almacén de MD. Esto ocurre al
                arrancar/recargar el servidor. A diferencia del resto de invocaciones, <directive>MDMessageCmd</directive> se ejecuta
                con permisos de root (en sistemas *nix) y tiene acceso a los archivos de certificado
                (y claves). Los certificados necesarios para otras aplicaciones o
                en formatos distintos pueden procesarse con este evento.
            </p><p>
                El evento 'renewing' se dispara antes de iniciar el proceso de renovación del
                 dominio administrado. Si el comando devuelve un valor distinto de 0 por este motivo, la renovación
                 se abortará y se repetirá en el siguiente ciclo. Algunas configuraciones en clúster usan esto para
                 permitir que las renovaciones se ejecuten solo en un único nodo.
            </p><p>
                El evento 'challenge-setup:type:domain' se dispara cuando se han creado los datos de desafío de un
                dominio. Esto se invoca antes de indicar al servidor ACME que los compruebe.
                El tipo es uno de los tipos de desafío ACME. Esto se invoca para cada
                nombre DNS de un MDomain. Las configuraciones en clúster pueden usar este evento para distribuir
                los archivos de desafío a todos los nodos del clúster.
            </p><p>
                'ocsp-errored' ocurre cuando <directive module="mod_md">MDStapling</directive>
                está activado para un dominio; indica
                que se encontró un error al obtener la respuesta OCSP de la
                Autoridad de Certificación. mod_md seguirá intentándolo.
            </p><p>
                'ocsp-renewed' se dispara cuando se ha obtenido correctamente una nueva respuesta
                OCSP para el certificado de un dominio. Este evento se dispara
                como máximo una vez al día.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDWarnWindow</name>
        <description>Define el margen de tiempo en el que quiere recibir un aviso sobre un certificado que está caducando.</description>
        <syntax>MDWarnWindow duration</syntax>
        <default>MDWarnWindow 10%</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Véase <directive module="mod_md">MDRenewWindow</directive> para una descripción de
                cómo puede especificar el tiempo.
            </p><p>
                El módulo comprueba la vida útil restante de los certificados e invoca
                <directive module="mod_md">MDMessageCmd</directive> cuando queda menos del margen de
                aviso indicado. Con el valor por defecto, esto significa 9 días para los certificados de
                Let's Encrypt.
            </p><p>
                También se aplica a los Dominios Administrados con archivos de certificado estáticos (véase
                <directive module="mod_md">MDCertificateFile</directive>).
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDServerStatus</name>
        <description>Controla si la información de los Dominios Administrados se añade a <code>server-status</code>.</description>
        <syntax>MDServerStatus on|off</syntax>
        <default>MDServerStatus off</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Si está activada, añade una sección a la
                salida del manejador '<code>server-status</code>' de <module>mod_status</module>
                que lista todos los Dominios Administrados con los nombres
                DNS, el estado de renovación, la vida útil y las propiedades principales.
            </p><p>
                Igual que con '<code>md-status</code>', la salida de '<code>server-status</code>'
                <strong>debe</strong> protegerse frente a la vista pública
                usando las restricciones de autorización adecuadas.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDCertificateMonitor</name>
        <description>La URL de un monitor de registros (logs) de certificados.</description>
        <syntax>MDCertificateMonitor name url</syntax>
        <default>MDCertificateMonitor crt.sh https://crt.sh?q=</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Esto forma parte de la interfaz de usuario HTML de '<code>server-status</code>' y no tiene nada
                que ver con el funcionamiento principal en sí. Define el enlace que se ofrece en esa
                página para comprobar fácilmente un monitor de certificados. La huella SHA256
                del certificado se añade a la url configurada.
            </p><p>
                Los Monitores de Certificados ofrecen supervisión de los Registros (logs) de Transparencia de Certificados (CT)
                para rastrear el uso de certificados de los dominios. Lo mínimo que puede comprobar
                es que Let's Encrypt (o la CA que haya configurado) ha introducido
                sus certificados en los CTLogs.
            </p><p>
                Advertencia: los registros de certificados se actualizan, y la recepción de esas
                actualizaciones por parte de los monitores sufre cierto retraso. Esto varía entre registros y monitores. Un
                certificado recién creado no se conocerá de inmediato.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDStapling</name>
        <description>Activa el stapling para todos los MDomain o para uno concreto.</description>
        <syntax>MDStapling on|off</syntax>
        <default>MDStapling off</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.42 y posteriores</compatibility>
        <usage>
            <p>
                <module>mod_md</module> ofrece una implementación para proporcionar información de OCSP stapling.
                Es una alternativa a la que ofrece <module>mod_ssl</module>. Por compatibilidad
                hacia atrás, está desactivada por defecto.
            </p><p>
                El stapling se puede activar para todos los certificados del servidor o
                para un <directive module="mod_md">MDomain</directive> concreto.
                Esto sustituirá cualquier configuración de stapling
                de <module>mod_ssl</module> para esos hosts. Cuando está desactivado, el stapling de <module>mod_ssl</module>
                hará el trabajo (si está activado, por supuesto). Esto permite
                una transición gradual de una implementación a la otra.
            </p><p>
                El stapling de <module>mod_md</module> también funcionará para dominios cuyos certificados
                no estén administrados por este módulo (véase <directive module="mod_md">MDStapleOthers</directive> para controlar esto).
                Esto permite usar el nuevo stapling sin usar ninguna gestión de certificados ACME.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDStapleOthers</name>
        <description>Activa el stapling para certificados no administrados por mod_md.</description>
        <syntax>MDStapleOthers on|off</syntax>
        <default>MDStapleOthers on</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.42 y posteriores</compatibility>
        <usage>
            <p>
                Esta configuración solo tiene efecto cuando <directive module="mod_md">MDStapling</directive> está activada. Controla
                si <module>mod_md</module> debe proporcionar también información de stapling para certificados
                que no están directamente controlados por él, p. ej. renovados mediante una CA ACME.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDStaplingKeepResponse</name>
        <description>Controla cuándo deben eliminarse las respuestas antiguas.</description>
        <syntax>MDStaplingKeepResponse <var>duration</var></syntax>
        <default>MDStaplingKeepResponse 7d</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.42 y posteriores</compatibility>
        <usage>
            <p>
                Este margen de tiempo especifica cuándo deben eliminarse de nuevo del almacén los datos
                de respuesta OCSP usados en el stapling. La información de respuesta con más de
                7 días (por defecto) se elimina al reiniciar/recargar el servidor. Esto evita
                que el almacén crezca cuando los certificados se renuevan/reconfiguran con frecuencia.
            </p><p>
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDStaplingRenewWindow</name>
        <description>Controla cuándo se renovarán las respuestas de stapling.</description>
        <syntax>MDStaplingRenewWindow <var>duration</var></syntax>
        <default>MDStaplingRenewWindow 33%</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.42 y posteriores</compatibility>
        <usage>
            <p>
                Si la validez de la respuesta OCSP usada en el stapling cae por debajo de <var>duration</var>,
                <module>mod_md</module> obtendrá una nueva respuesta OCSP.
            </p><p>
                La CA que emite un certificado suele operar también el servicio respondedor OCSP
                y determina durante cuánto tiempo es válida su propia respuesta firmada sobre la validez
                de un certificado. Cuanto más tiempo sea válida una respuesta, más tiempo se
                puede almacenar en caché, lo que supone un mejor rendimiento general para todos.
                Cuanto más corta sea su vida útil, más rápido se propagan las revocaciones de
                certificados a los clientes. Además, la fiabilidad del servicio es otra consideración.
            </p><p>
                Ajustando el margen de renovación del stapling puede controlar parte de esto usted mismo.
                Si hace que el tiempo de renovación sea corto (p. ej. poco antes de que caduque la información
                actual), obtiene el máximo tiempo de caché. Pero una interrupción del servicio
                (por mantenimiento, por ejemplo) le afectará. Si renueva mucho tiempo
                antes de la caducidad, las actualizaciones serán más frecuentes, generarán más carga
                en la infraestructura del servidor de la CA y también más coordinación entre
                los procesos hijos de su servidor.
            </p><p>
                El valor por defecto se ha elegido en 33%, lo que significa que la renovación se inicia cuando solo
                queda un tercio de la vida útil de la respuesta. Para una CA que emite respuestas OCSP
                con una vida útil de 3 días, esto significa 2 días de caché y 1 día
                para los intentos de renovación. Una interrupción del servicio tendría que durar 24 horas
                completas para afectar a sus dominios.
            </p><p>
                También es posible establecer un margen de renovación absoluto, como `2d` (2 días).
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDCertificateCheck</name>
        <description>Establece el nombre y el patrón de URL de un sitio de monitorización de certificados.</description>
        <syntax>MDCertificateCheck <var>name</var> <var>url</var></syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.42 y posteriores</compatibility>
        <usage>
            <p>
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDActivationDelay</name>
        <description>Cuánto tiempo retrasar la activación de los nuevos certificados</description>
        <syntax>MDActivationDelay <var>duration</var></syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.42 y posteriores</compatibility>
        <usage>
            <p>
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDContactEmail</name>
        <description>Dirección de correo usada para el registro de la cuenta</description>
        <syntax>MDContactEmail <var>address</var></syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.42 y posteriores</compatibility>
        <usage>
            <p>
                El protocolo ACME exige que proporcione una url de contacto al registrarse. Actualmente,
                Let's Encrypt pide una dirección de correo (y la usará para informarle sobre renovaciones
                o cambios en los términos del servicio). <module>mod_md</module> usa el correo de la directiva <directive>MDContactEmail</directive> en
                su configuración de Apache, así que indique ahí la dirección correcta.
                Si <directive>MDContactEmail</directive> no está presente, <module>mod_md</module> usará la
                directiva <directive module="core">ServerAdmin</directive>.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDExternalAccountBinding</name>
        <description>Establece el keyid y los valores hmac de vinculación de cuenta externa a usar en la CA</description>
        <syntax>MDExternalAccountBinding <var>key-id</var> <var>hmac-64</var> | none | <var>file</var></syntax>
        <default>MDExternalAccountBinding none</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.52 y posteriores</compatibility>
        <usage>
            <p>
                Configura los valores para la "External Account Binding" de ACME, una característica
                del estándar ACME que permite a los clientes vincular sus registros
                a una cuenta de cliente ya existente en los servidores ACME.
            </p>
            <p>
                Let's Encrypt no los requiere, pero otras CA ACME sí.
                Consulte con su CA ACME si los necesita y cómo obtener los
                valores. Son dos cadenas de texto, un identificador de clave y un valor
                'hmac' codificado en base64.
            </p>
            <p>
                Puede configurarlos de forma global o para un MDomain concreto. Dado que
                estos valores permiten a cualquiera registrarse con la misma cuenta, es
                recomendable dar permisos restringidos al archivo de configuración,
                por ejemplo, solo para root.
            </p>
            <p>
                El valor también se puede tomar de un archivo JSON, para mantener permisos más
                abiertos en la configuración del servidor y restringir los de ese
                archivo. El propio JSON es:
            </p>
            <example><title>Archivo de Ejemplo JSON EAB</title>
                <highlight language="config">
{"kid": "kid-1", "hmac": "zWND..."}
                </highlight>
            </example>
            <p>
                Si cambia los valores EAB, los nuevos se usarán cuando llegue la siguiente
                renovación de certificado.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDRetryDelay</name>
        <description>Duración del primer reintento, que se duplica en cada error consecutivo.</description>
        <syntax>MDRetryDelay <var>duration</var></syntax>
        <default>MDRetryDelay 30s</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.54 y posteriores</compatibility>
        <usage>
            <p>
                El tiempo de espera tras un error antes de intentar
                renovar un certificado de nuevo. Esta duración se duplica después
                de cada error consecutivo, con un máximo de 24 horas.
            </p>
            <p>
                Se mantiene de forma independiente para cada renovación de certificado. Es decir, un error
                en un MDomain no retrasa las renovaciones de otros dominios.
            </p>
            <p>
                En mod_md v2.6.1, el retraso por defecto se ha aumentado de 5
                segundos a 30.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDRetryFailover</name>
        <description>El número de errores antes de que se dispare el cambio a otra CA</description>
        <syntax>MDRetryFailover <var>number</var></syntax>
        <default>MDRetryFailover 13</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.54 y posteriores</compatibility>
        <usage>
            <p>
                El número de errores consecutivos al renovar un certificado antes de que
                se seleccione otra CA. Esto solo se aplica a las configuraciones que
                tienen especificada más de una <directive module="mod_md">MDCertificateAuthority</directive>.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDStoreLocks</name>
        <description>Configura el bloqueo del almacén para las actualizaciones</description>
        <syntax>MDStoreLocks on|off|<var>duration</var></syntax>
        <default>MDStoreLocks off</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.55 y posteriores</compatibility>
        <usage>
            <p>
                Active esto para usar un archivo de bloqueo al arrancar el servidor, cuando
                <directive module="mod_md">MDStoreDir</directive> se sincroniza con la configuración del
                servidor y se activan los certificados renovados.
            </p><p>
                El bloqueo está pensado para configuraciones en clúster que tienen un sistema de
                archivos compartido para <directive module="mod_md">MDStoreDir</directive>.
                Protegerá la activación de
                los certificados renovados cuando los nodos del clúster se reinicien/recarguen
                al mismo tiempo. Siempre que el sistema de archivos
                 compartido soporte bloqueo de archivos.
            </p><p>
                La duración por defecto para obtener el bloqueo es de 5 segundos. Si el bloqueo
                no se puede obtener, se registra un error y el arranque del servidor
                continúa. Esto puede hacer que un nodo del clúster siga usando
                el certificado anterior después.
            </p><p>
                Un tiempo de espera más alto reducirá esa probabilidad, pero puede retrasar los
                arranques/recargas del servidor si los bloqueos no se gestionan correctamente en
                el sistema de archivos subyacente. Una instancia de httpd solo debería mantener
                un bloqueo durante un breve periodo de tiempo.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDChallengeDns01Version</name>
        <description>Establece el tipo de argumentos con los que se llama a MDChallengeDns01</description>
        <syntax>MDChallengeDns01Version 1|2</syntax>
        <default>MDChallengeDns01Version 1</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.58 y posteriores</compatibility>
        <usage>
            <p>
                Establece la forma en que se invoca el comando <directive module="mod_md">MDChallengeDns01</directive>,
                p. ej. el número y los tipos de argumentos.
                Véase <directive module="mod_md">MDChallengeDns01</directive>
                para conocer las diferencias.
            </p><p>
                Esta configuración es global y no se puede variar por dominio.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDMatchNames</name>
        <description>Determina cómo se emparejan los nombres DNS con los vhosts</description>
        <syntax>MDMatchNames all|servernames</syntax>
        <default>MDMatchNames all</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.58 y posteriores</compatibility>
        <usage>
            <p>
                El modo `all` es el comportamiento de todas las versiones anteriores. Se examinan
                tanto <directive module="core">ServerName</directive>
                como <directive module="core">ServerAlias</directive> para
                encontrar el <directive module="mod_md">MDomain</directive> que coincide con un VirtualHost.
                Esto detecta automáticamente la cobertura, incluso cuando solo haya añadido
                uno de los nombres a un MDomain.
            </p><p>
                Sin embargo, esta magia automática tiene inconvenientes en configuraciones más complejas. Si establece
                esta directiva a `servernames`, solo se usa el ServerName de un servidor virtual para
                el emparejamiento. Los ServerAlias se ignoran entonces para el emparejamiento.
                Los alias seguirán añadiéndose al certificado obtenido, a menos que también
                ejecute `MDMembers manual`.
            </p><p>
                Otra ventaja de `servernames` es que le da más flexibilidad
                con subdominios y wildcards. Puede definir un MDomain con un wildcard
                y tener otros MDomain para nombres de subdominios específicos.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDCheckInterval</name>
        <description>Determina con qué frecuencia se comprueban los certificados</description>
        <syntax>MDCheckInterval <var>duration</var></syntax>
        <default>MDCheckInterval 12h</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.60 y posteriores</compatibility>
        <usage>
            <p>
                El tiempo entre comprobaciones de certificados. Por defecto, la validez
                y la necesidad de renovación se comprueban dos veces al día. Este intervalo
                no se sigue de forma precisa. En su lugar, el módulo aplica aleatoriamente
                una variación de +/-50%. Con el valor por defecto de 12 horas, esto
                significa que el tiempo real entre ejecuciones varía entre 6 y 18
                horas, variando de nuevo en cada ejecución. Esto ayuda a mitigar
                los picos de tráfico en los servidores ACME.
            </p><p>
                La duración mínima que puede configurar es 1 segundo. No se
                recomienda usar tiempos tan cortos en producción.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDProfile</name>
        <description>Usa un perfil ACME específico de la CA</description>
        <syntax>MDProfile name</syntax>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.64 y posteriores</compatibility>
        <usage>
            <p>
                Esto trata sobre una extensión ACME no estándar de Let's Encrypt.
            </p><p>
                Let's Encrypt soporta Perfiles de Certificado en su CA. Esto,
                entre otros detalles, le permite seleccionar la vida útil de los
                certificados que obtiene. El perfil "classic" es el valor por defecto y
                mantiene los 90 días; el perfil "tlsserver" también es de 90 días,
                con un máximo de 25 Nombres Alternativos del Sujeto. El perfil "shortlived"
                emitirá certificados con solo 6 días de validez.
            </p><p>
                Si no cambia su configuración de <module>mod_md</module>, seguirá
                obteniendo certificados de 90 días. Si cree
                que una vida útil más corta le resulta beneficiosa (y asume el
                riesgo de que el tiempo de renovación sea mucho más corto),
                puede configurar el perfil a usar mediante 'MDProfile shortlived'.
           </p><p>
                Los nombres de perfil los define la CA. Si un perfil que
                configura no está disponible, no se usará ningún perfil y
                el certificado se emitirá según lo que la CA
                considere por defecto.
           </p><p>
                Véase <directive module="mod_md">MDProfileMandatory</directive>
                para saber cómo desactivar los valores por defecto de los perfiles.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDProfileMandatory</name>
        <description>Controla si un MDProfile es obligatorio.</description>
        <syntax>MDProfileMandatory on|off</syntax>
        <default>MDProfileMandatory off</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.64 y posteriores</compatibility>
        <usage>
            <p>
                Controla si un <directive module="mod_md">MDProfile</directive>
                que configure es obligatorio o no. Cuando es obligatorio y la CA
                no ofrece el perfil configurado, la renovación del
                certificado fallará.
           </p><p>
                Cuando no es obligatorio y la CA no ofrece un perfil,
                las renovaciones se realizarán sin especificar un perfil y
                la CA emitirá los certificados según sus valores por defecto.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDRenewViaARI</name>
        <description>uso de la extensión ACME ARI (rfc9773).</description>
        <syntax>MDRenewViaARI on|off</syntax>
        <default>MDRenewViaARI on</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <usage>
            <p>
                Activa/desactiva las renovaciones de certificados disparadas mediante la
                extensión ACME ARI (rfc9773). Estas renovaciones ocurren *además de*
                el mecanismo controlado por <directive module="mod_md">MDRenewWindow</directive>.
           </p><p>
                ACME ARI permite a una CA ACME moderar en cierta medida el tráfico
                de renovaciones entrante. Pero, más importante aún, puede informar a los
                clientes de renovaciones urgentes, por ejemplo cuando se ha revocado un certificado
                o parte de su cadena.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDInitialDelay</name>
        <description>Cuánto tiempo retrasar la primera comprobación de certificados.</description>
        <syntax>MDInitialDelay <var>duration</var></syntax>
        <default>MDInitialDelay 0s</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Disponible en la versión 2.4.66 y posteriores</compatibility>
        <usage>
            <p>
                El tiempo de espera tras el arranque del servidor antes de comprobar las
                renovaciones de certificados. Por defecto esto ocurre de inmediato.
            </p>
        </usage>
    </directivesynopsis>

    <directivesynopsis>
        <name>MDCACertificateFile</name>
        <description>Archivo que contiene las anclas de confianza x509 para verificar los servidores ACME.</description>
        <syntax>MDCACertificateFile <var>file</var></syntax>
        <default>MDCACertificateFile none</default>
        <contextlist>
            <context>server config</context>
        </contextlist>
        <compatibility>Desde la versión 2.4.69, esto se puede configurar por separado para cada MDomain.</compatibility>
        <usage>
            <p>
                Esto se usa principalmente en configuraciones de pruebas donde el módulo necesita
                conectarse a un servidor ACME de pruebas que tiene su propio certificado raíz.
                Quienes gestionan una CA interna corporativa pueden usar esto cuando
                ejecutan sus propios servidores ACME.
            </p>
            <p>
                Use "none" como ruta para desactivarlo explícitamente.
            </p>
        </usage>
    </directivesynopsis>
</modulesynopsis>
