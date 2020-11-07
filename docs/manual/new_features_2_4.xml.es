<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1855701:1883045 (outdated) -->
<!-- Spanish Translation by: Luis Gil de Bernabé -->
<!-- Reviewed by: Sergio Ramos -->

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

<manualpage metafile="new_features_2_4.xml.meta">

<title>Información General sobre las Nuevas Características en Apache HTTP Server 2.4</title>

<summary>
  <p>Este documento describe algunos de los principales cambios entre las  versiones
     2.2 y 2.4 del Servidor Apache HTTP. Para las nuevas características desde
     versión 2.0, consulte el  documento <a href="new_features_2_2.html"> 2.2 nuevas características.</a></p>
</summary>

  <section id="core">
    <title>Mejoras en el Core</title>
    <dl>
      <dt>Cargas de  MPM en Tiempo de Ejecución</dt>
      <dd>Múltiples MPMs ahora se pueden <a href="mpm.html#dynamic"> construir 
      como módulos dinámicos </a>de forma  que pueden ser cargados en tiempo de compilación.
      El MPM de elección se puede configurar en tiempo de ejecución a través 
      de <directive module="mod_so"> LoadModule </directive>.</dd>

      <dt>Evento MPM</dt>
      <dd>El <a href="mod/event.html">Evento MPM</a> ya no es experimental, lo cuál ahora está totalmente soportado.</dd>

      <dt>Soporte Asíncrono (Asynchronous)</dt>
      <dd>Mejor soporte para lectura y escritura asíncrona para soporte de MPM y
      otras plataformas.</dd>

      <dt>Configuración del Nivel de Log (LogLevel) por Módulo y Directorio</dt>
      <dd>El <directive module="core">LogLevel</directive>  puede ser configurado ahora 
      por módulo y por directorio. Nuevos niveles de <code>trace1</code>
      a <code>trace8</code> se han añadido por encima de la etiqueta  de nivel de 
      registro de log <code>debug</code>.</dd>

      <dt>Secciones de Configuración por Petición</dt>
      <dd><directive module="core" type="section">If</directive>,
          <directive module="core" type="section">ElseIf</directive>,
          y <directive module="core" type="section">Else</directive> se pueden usar 
          para establecer los criterios de configuración por cada petición.</dd>

      <dt>Analizador de Expresión de Uso General</dt>
      <dd>Un nuevo analizador de expresiones permite especificar
          <a href="expr.html">condiciones complejas</a> utilizando una sintaxis común
          en directivas como
          <directive module="mod_setenvif">SetEnvIfExpr</directive>,
          <directive module="mod_rewrite">RewriteCond</directive>,
          <directive module="mod_headers">Header</directive>,
          <directive module="core" type="section">If</directive>,
          entre otras.
      </dd>

      <dt>KeepAliveTimeout en Milisegundos</dt>
      <dd>Ahora es posible especificar <directive module="core"
      >KeepAliveTimeout</directive> en milisegundos.
      </dd>

      <dt>Directiva NameVirtualHost</dt>
      <dd>Ya no es necesario y ahora está en desuso.</dd>

      <dt>Anular Configuración</dt>
      <dd>La nueva directiva <directive module="core">AllowOverrideList</directive>
          permite un control más exhaustivo de que directivas se permiten en los archivos <code>.htaccess</code>.</dd>

      <dt>Variables de los Archivos de Configuración</dt>
      <dd>Ahora es posible <directive module="core">Definir</directive>
          variables en la configuración, lo que permite una representación más clara
          si el mismo valor se utiliza en muchos lugares en la configuración.
      </dd>

      <dt>Reducción del Uso de Memoria</dt>
      <dd>A pesar de muchas de las nuevas características, 2.4.x tiende a usar menos 
      	memoria que la versión 2.2.x. </dd>

    </dl>
  </section>

  <section id="newmods">
    <title>Nuevos Módulos</title>
    <dl>
      <dt><module>mod_proxy_fcgi</module></dt>
      <dd>Protocolo FastCGI backend para<module>mod_proxy</module></dd>

      <dt><module>mod_proxy_scgi</module></dt>
      <dd>Protocolo SCGI backend para <module>mod_proxy</module></dd>

      <dt><module>mod_proxy_express</module></dt>
      <dd>Proporciona una configuración masiva y dinámica de proxys inversos para
      <module>mod_proxy</module></dd>

      <dt><module>mod_remoteip</module></dt>
      <dd>Reemplaza la dirección IP remota cliente aparente y nombre de host para la solicitud
      con la lista de direcciones IP presentada por un proxy o un balanceador de carga a través de
      las cabeceras de solicitud.</dd>

      <dt><module>mod_heartmonitor</module>,
          <module>mod_lbmethod_heartbeat</module></dt>
      <dd>Permite a <module>mod_proxy_balancer</module> basar las decisiones del balanceo de 
      carga según el número de conexiones activas en los servidores de back-end.</dd>

      <dt><module>mod_proxy_html</module></dt>
      <dd>antiguamente un módulo de terceros, esto apoya la fijación de enlaces 
        HTML en un proxy inverso, situación en la que el servidor genera URLs 
        que no son válidas para los clientes del proxy.</dd>

      <dt><module>mod_sed</module></dt>
      <dd>Un reemplazo avanzado de <module>mod_substitute</module>, permite editar el 
      cuerpo de la respuesta con el poder lleno de sed.</dd>

      <dt><module>mod_auth_form</module></dt>
      <dd>Habilitar la autenticación basada en formularios.</dd>

      <dt><module>mod_session</module></dt>
      <dd>Permite el uso de estado de sesión para clientes, utilizando cookies o 
      	almacenamiento en una base de datos.</dd>

      <dt><module>mod_allowmethods</module></dt>
      <dd>Nuevo módulo para restringir ciertos métodos HTTP sin interferir con
      autenticación o autorización.</dd>

      <dt><module>mod_lua</module></dt>
      <dd>Embebe el lenguaje<a href="http://www.lua.org/">Lua</a> en httpd,
      para la configuración y las funciones lógicas de negocios pequeños. (Experimental)</dd>

      <dt><module>mod_log_debug</module></dt>
      <dd>Permite añadir mensajes de depuración personalizados en las diferentes fases del procesamiento de la solicitud.</dd>

      <dt><module>mod_buffer</module></dt>
      <dd>Proporciona almacenamiento en búfer para los filtros de entrada y salida de las pilas</dd>

      <dt><module>mod_data</module></dt>
      <dd>Convierte la respuesta del cuerpo en una dirección URL de datos RFC2397</dd>

      <dt><module>mod_ratelimit</module></dt>
      <dd>Proporciona limitación de velocidad en el ancho de banda para los clientes</dd>

      <dt><module>mod_request</module></dt>
      <dd>Proporciona filtros para manejar y hacer el cuerpo de la petición HTTP disponibles</dd>

      <dt><module>mod_reflector</module></dt>
      <dd>Proporciona Reflexión del cuerpo de la petición como una respuesta a través de la pila de filtro de salida.</dd>

      <dt><module>mod_slotmem_shm</module></dt>
      <dd>Proporciona un proveedor de memoria compartida basada en huecos (ala the scoreboard).</dd>

      <dt><module>mod_xml2enc</module></dt>
      <dd>Anteriormente un módulo de terceros, que apoya la internacionalización en
      módulos de filtro (markup-aware) basada en libxml2.</dd>

      <dt><module>mod_macro</module> (disponible desde la versión 2.4.5)</dt>
      <dd>Provee macros para los archivos de configuración</dd>

      <dt><module>mod_proxy_wstunnel</module> (disponible desde la versión 2.4.5)</dt>
      <dd>Soporte a túneles web-socket.</dd>

      <dt><module>mod_authnz_fcgi</module> (disponible desde la versión 2.4.10)</dt>
      <dd>Habilitar aplicaciones autorizadas FastCGI para autenticar y/o autorizar a los clientes.</dd>

      <dt><module>mod_http2</module> (disponible desde la versión 2.4.17)</dt>
      <dd>Soporte para la capa HTTP/2</dd>

      <dt><module>mod_proxy_hcheck</module> (disponible desde la versión 2.4.21)</dt>
      <dd>Soporta controles dinámicos propios del estado de servidores proxys remotos</dd>

      <dt><module>mod_brotli</module> (disponible desde la versión 2.4.26)</dt>
      <dd>Soporte para el algoritmo de compresión Brotli.</dd>

      <dt><module>mod_md</module> (disponible desde la versión 2.4.30)</dt>
      <dd>Soporte para el protocolo ACME para la automatización del proceso de 
        aprovisionamiento de certificados.</dd>

      <dt><module>mod_socache_redis</module> (disponible desde la versión 2.4.39)</dt>
      <dd>Soporte para caché de objetos compartidos basados en <a href="htt://redis.io/">Redis</a>.</dd>

    </dl>
  </section>

  <section id="module">
    <title>Mejoras de Módulos.</title>
    <dl>
      <dt><module>mod_ssl</module></dt>

      <dd><module>mod_ssl</module> ahora puede ser configurado para utilizar un servidor 
      OCSP para comprobar el estado de validez de un certificado de cliente. La respuesta por 
      defecto es configurable, junto con la decisión sobre si se debe preferir el "responder"
       designado en el certificado de cliente en sí.</dd>

      <dd><module>mod_ssl</module> ahora también es compatible con "OCSP stapling", 
      una respuesta de OCSP al inicial TLS "Handshake" con marca de tiempo 
      firmado por la CA , en el que el servidor obtiene de forma proactiva 
      una verificación OCSP de su certificado y transmite esa o la del cliente
       durante el  "Handshake".</dd>


      <dd><module>mod_ssl</module> Ahora se puede configurar para compartir los datos de 
      sesión SSL entre servidores a través de memcached.</dd>

      <dd>Claves de cifrado de tipo EC (Curva Elíptica en Inglés) son ahora 
      	soportadas junto con RSA y DSA.</dd>

      <dd>Soporte de TLS-SRP (disponible en la versión 2.4.4 y posteriores).</dd>

      <dt><module>mod_proxy</module></dt>

      <dd>La directiva <directive module="mod_proxy">ProxyPass</directive> 
      ahora está configurado de forma más óptima dentro de un bloque
      <directive module="core">Location</directive> o
      <directive module="core">LocationMatch</directive>,
      y ofrece una ventaja de rendimiento significativa sobre la sintaxis tradicional
      de dos parámetros cuando están presentes en gran número.</dd>
      <dd>La dirección de origen utilizada para solicitudes de proxy es ahora configurable.</dd>
      <dd>Soporte para sockets de dominio Unix en el backend (disponible en la versión 2.4.7
      y posteriores).</dd>

      <dt><module>mod_proxy_balancer</module></dt>

      <dd>Más cambios en la configuración en tiempo de ejecución para BalancerMembers 
      	mediante el configurador del balanceador.</dd>

      <dd>Se pueden agregar miembros adicionales a BalancerMembers en tiempo de ejecución 
      	mediante el configurador del balanceador.</dd>

      <dd>Configuración de ejecución de un subconjunto de parámetros Balancer</dd>

      <dd>BalancerMembers se puede establecer en "fuga" de modo que sólo responden a las 
      	sesiones problemáticas existentes, lo que les permite ser puestos con gracia fuera de línea.</dd>

      <dd>Configuración del balanceador de carga pueden ser persistentes después de un reinicio.</dd>

      <dt><module>mod_cache</module></dt>

      <dd>En el módulo <module>mod_cache</module> se puede añadir filtro de cache en determinado 
      punto en la cadena de filtro, para proveer mejor control de la caché</dd>

      <dd><module>mod_cache</module> Puede cachear ahora peticiones de tipo HEAD.</dd>
      <dd>Siendo posible ahora las directivas <module>mod_cache</module>
      ser configuradas por directorio en vez de por servidor.</dd>

      <dd>La URL base de las URLs cacheadas se pueden personalizar, 
      de tal forma que un cluster de cachés puede compartir el mismo
      prefijo URL de punto final.</dd>

      <dd><module>mod_cache</module> ahora es capaz de servir a los datos en caché 
      antigua cuando un motor no está disponible (error 5xx).</dd>

      <dd><module>mod_cache</module> ahora puede insertar HIT/MISS/REVALIDATE 
      en una cabecera de tipo X-Cache.</dd>

      <dt><module>mod_include</module></dt>
      <dd>Soporte al atributo 'onerror' dentro del elemento 'include', lo que permite
      mostar un documento de error cuando hay un error en vez de la cadena de error por defecto.
      </dd>

      <dt><module>mod_cgi</module>, <module>mod_include</module>,
          <module>mod_isapi</module>, ...</dt>
      <dd>La traducción de cabeceras a variables de entorno es más estricta que antes para mitigar 
      algunos de los posibles ataques de cross-site scripting, a través de la inyección de cabecera. 
      Las cabeceras que contienen carácteres no válidos (incluyendo guiones bajos)
      son descartadas de forma silenciosa. <a href="env.html">Las variables de entorno en
      Apache</a> tienen algunos consejos en como trabajar con clientes con sistemas heredados rotos que 
      requieren de este tipo de cabeceras. (Esto afecta a todos los módulos que 
      usan éstas variables de entorno.)</dd>

      <dt><module>mod_authz_core</module> Autorización Lógica de Contenedores</dt>

      <dd>Ahora puede ser especificada una lógica avanzada de autorización, usando la directiva 
          <directive module="mod_authz_core">Require</directive> y 
          las directivas de los contenedores asociados, tales como
          <directive module="mod_authz_core"
          type="section">RequireAll</directive>.</dd>

      <dt><module>mod_rewrite</module></dt>
      <dd><module>mod_rewrite</module> añade los flags <code>[QSD]</code>
          (Query String Discard) y <code>[END]</code> para las directivas
          <directive module="mod_rewrite">RewriteRule</directive> para 
          simplificar escenarios de reescritura comunes.</dd>
      <dd>Añade la posibilidad de usar expresiones buleanas complejas en <directive
          module="mod_rewrite">RewriteCond</directive>.</dd>
      <dd>Permite el uso de queris SQL como funciones de <directive
          module="mod_rewrite">RewriteMap</directive>.</dd>

      <dt><module>mod_ldap</module>, <module>mod_authnz_ldap</module></dt>
      <dd><module>mod_authnz_ldap</module> agrega soporte a grupos anidados.</dd>
      <dd><module>mod_ldap</module> Incorpora
          <directive module="mod_ldap">LDAPConnectionPoolTTL</directive>,
          <directive module="mod_ldap">LDAPTimeout</directive>, y otras mejoras
           en el manejo de los "timeouts" tiempo agotado de espera.
          Esto es especialmente útil para escenarios en los que existe un firewall 
          en modo "Stateful" que desecha conexiones inactivas a un servidor LDAP.</dd>
      <dd><module>mod_ldap</module> Incorpora
          <directive module="mod_ldap">LDAPLibraryDebug</directive> para registrar información de 
          depuración proporcionada por el conjunto de herramientas usadas por LDAP.</dd>

      <dt><module>mod_info</module></dt>
      <dd><module>mod_info</module> ahora puede volcar la configuración pre-procesada
      a la salida estándar durante el inicio del servidor.</dd>

      <dt><module>mod_auth_basic</module></dt>
      <dd>Nuevo mecanismo genérico para la autenticación básica falsa (disponible en la versión
      2.4.5 y posteriores).</dd>

    </dl>
  </section>

  <section id="programs">
    <title>Mejoras para el Programa</title>
    <dl>
        <dt><program>fcgistarter</program></dt>
        <dd>Nuevo demonio FastCGI como utilidad de arranque</dd>

        <dt><program>htcacheclean</program></dt>
        <dd>Ahora las URLs cacheadas actualmente, pueden ser listadas, con meta-datos adicionales incluidos.</dd>
        <dd>Permite el borrado explicito y selectivo de URLs cacheadas.</dd>
        <dd>Los tamaños de archivo ahora se pueden redondear hasta el tamaño de bloque determinado,
        por lo que los límites de tamaño se asemeja más estrechamente con el tamaño real en el disco.</dd>
        <dd>El tamaño de la caché ahora puede ser limitado por el número de i-nodos, 
        en vez de o como añadido, al limite del tamaño del archivo en el disco.</dd>

        <dt><program>rotatelogs</program></dt>
        <dd>Ahora puede crear un enlace al propio fichero de log.</dd>
        <dd>Ahora puede invocar a un escript personalizado pos-rotate.</dd>

        <dt><program>htpasswd</program>, <program>htdbm</program></dt>
        <dd>Soporta el algoritmo bcrypt (disponible en la versión 2.4.4 y posteriores).
        </dd>
    </dl>
  </section>

  <section id="documentation">
    <title>Documentación</title>
    <dl>
        <dt>mod_rewrite</dt>
        <dd>La documentación de  <module>mod_rewrite</module> ha sido reorganizada
        y casi escrita por completo, poniendo énfasis en ejemplos y modos de empleo
        más comunes, así como enseñarle que otras soluciones son más apropiadas.

        La <a href="rewrite/">guía del módulo Rewrite</a> es ahora ahora es una 
        sección de nivel superior con mucho más detalle y una mejor organización.</dd>

        <dt>mod_ssl</dt>
        <dd>La documentación del módulo <module>mod_ssl</module> ha sido mejorada en gran medida,
        con más ejemplos a nivel de la instalación inicial, además del enfoque técnico anterior.</dd>

        <dt>Guía de Cachés</dt>
        <dd>La <a href="caching.html">guía de caché</a> ha sido reescrita para distinguir propiamente 
        entre la caché del RFC2616 HTTP/1.1 y sus características
        aportadas por <module>mod_cache</module>, y el caso general de cache de valor/clave
        aportado por la interfaz <a href="socache.html">socache</a>,
        así como cubrir temas específicos  como los mecanismos de caché aportados por el módulo
        <module>mod_file_cache</module>.</dd>

    </dl>
  </section>

  <section id="developer">
    <title>Cambios en los Desarrollos de Módulos</title>
    <dl>
      <dt>Añadido Hook de Comprobación de Configuración</dt>

      <dd>El nuevo Hook, <code>check_config</code>, ha sido añadido el cuál se ejecuta entre
      	  los hooks <code>pre_config</code> y <code>open_logs</code>.
      	  También se ejecuta antes del hook <code>test_config</code> cuando la opción 
          <code>-t</code> se le pasa al <program>httpd</program>. El hook <code>
          check_config</code> permite a los módulos revisar los valores en las 
          directivas de configuraciones de forma independiente y ajustarlos mientras 
          mensajes pueden seguir siendo logados a la consola.

          El usuario puede así ser alertado de problemas de mala 
          configuración antes de que la función hook <code>open_logs</code> 
          redireccione la salida de la consola
          al log de error.</dd>

      <dt>Añadido un Analizador de Expresiones</dt>

      <dd>Ahora tenemos un analizador de expresiones de propósito general, y su API está
      expuesta en <var>ap_expr.h</var>. Esto es una adaptación del que había anteriormente
      implementado en <module>mod_ssl</module>.</dd>

      <dt>Autorización Lógica de Contenedores</dt>

      <dd>Los módulos de autorización ahora se registran como un proveedor, mediante
      <code>ap_register_auth_provider()</code>, para soportar lógicas de autorización avanzadas,
      como la directiva <directive module="mod_authz_core" type="section"
      >RequireAll</directive>.</dd>

      <dt>Interfaz de Almacenamiento en Caché de Objetos Pequeños</dt>

      <dd>La cabecera <var>ap_socache.h</var> expone una interfaz basada en proveedor
      de objetos de datos para la captura de pequeños, basado en la 
      aplicación anterior de caché de sesión del módulo <module>mod_ssl</module>.
      Los proveedores que utilizan una memoria compartida de búfer cíclico, 
      archivos dbf basados en disco, y una memoria caché distribuida
      memcache están soportados actualmente.</dd>

      <dt>Añadido Hook de Estado de la Caché</dt>

      <dd>El módulo <module>mod_cache</module> ahora incluye un nuevo hook
      <code>cache_status</code>, que es llamado cuando las 
      decisiones de caché son conocidas. Se provee una implementación
      por defecto que añade a la cabecera de la respuesta de forma
      opcional <code>X-Cache</code> y <code>X-Cache-Detail</code>.</dd>
    </dl>

    <p>La documentación de desarrolladores contiene una 
    <a href="developer/new_api_2_4.html">lista detallada de los cambios realizados
    en la API</a>.</p>
  </section>

</manualpage>
