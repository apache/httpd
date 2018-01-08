<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1561569 -->
<!-- Translated by: Luis Gil de Bernabé Pfeiffer lgilbernabe[AT]apache.org-->
<!-- Review by Sergio Ramos -->
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

<manualpage metafile="new_features_2_2.xml.meta">

<title>Información General sobre las Nuevas Características en Apache HTTP Server 2.2</title>

<summary>
  <p>Este documento describe algunos de los principales cambios entre las versiones 2.0 y
   2.2 del Servidor Apache HTTP. Para las nuevas características desde la versión 1.3, 
   consulte <a href="new_features_2_0.html">2.0 nuevas características.</a>
  </p>
</summary>

  <section id="core">
    <title>Mejoras principales</title>
    <dl>

      <dt>Autenticación y Autorización</dt>
      <dd>El paquete de los módulos de autenticación y autorización se han 
      refactorizado. El nuevo módulo mod_authn_alias (eliminados en las 
      versiones 2.3/2.4) puede simplificar de gran forma algunas configuraciones 
      de autenticación. Vea también el <a href="#module">cambio de nombres de 
      los módulos</a>, y <a href="#developer">los cambios para desarrolladores</a> 
      para más información sobre los cambios de como afectan a los usuarios, 
      y a los que desarrollan módulos.
      </dd>

      <dt>Caché</dt>
      <dd><module>mod_cache</module>, <module>mod_cache_disk</module>, y
          mod_mem_cache (eliminados en las versiones 2.3/2.4) han sufrido muchos 
          cambios, y ahora se consideran en calidad de producción. 
          El programa <program>htcacheclean</program> se ha introducido
          para limpiar los setups de <module>mod_cache_disk</module>.
      </dd>

      <dt>Configuración</dt>
      <dd>La capa de la configuración por defecto, se ha simplificado y 
      modularizado. Se pueden utilizar fragmentos de configuración para 
      habilitar las funciones de uso común que ahora se incluyen con Apache, 
      y pueden ser fácilmente añadidos a la configuración del servidor
      principal.</dd>

      <dt>Detención con elegancia</dt>
      <dd>Los módulos <module>prefork</module>, <module>worker</module> y
          <module>event</module> MPMs(módulos de procesos múltiples) ahora 
          permiten a <program>httpd</program> ser apagado/parado con elegancia
          mediante la señal 
          <a href="stopping.html#gracefulstop"><code>graceful-stop</code></a>.
          La directiva <directive
          module="mpm_common">GracefulShutdownTimeout</directive> se ha añadidos
          para especificar un tiempo opcional, tras el cual el 
          <program>httpd</program> se parará independientemente del estado de
          cualquier petición que se esté sirviendo.</dd>

      <dt>Funcionalidad del Proxy</dt>
      <dd>El nuevo módulo <module>mod_proxy_balancer</module> proporciona un 
      servicio de balanceo de carga para el módulo <module>mod_proxy</module>.
      El nuevo módulo <module>mod_proxy_ajp</module> añade soporte para el
      <code>Protocolo  JServ versión 1.3 de Apache </code> usado por
          <a href="http://tomcat.apache.org/">Apache Tomcat</a>.</dd>

      <dt>Actualización de la Librería de Expresiones Regulares</dt>
      <dd>Se ha incluido la versión 5.0 de 
          <a href="http://www.pcre.org/">Librería de Expresiones Regulares 
          Compatibles Perl </a> (PCRE). El programa <program>httpd</program> 
          puede ser configurado para que use una instalación en el sistema 
          de PCRE pasandole como parámetro <code>--with-pcre</code> 
          al configure.</dd>

      <dt>Filtrado Inteligente</dt>
      <dd><module>mod_filter</module> introduce una configuración dinámica 
      a la cadena de filtro de salida. Habilita que los filtros sean insertados
      de forma condicional, basado en cualquier cabecera de petición o respuesta
      o una variable de entorno, y prescinde de las dependencias más problemáticas
      así como problemas de ordenación en la arquitectura 2.0.</dd>

      <dt>Soporte de Grandes Ficheros</dt>
      <dd><program>httpd</program> es creado ahora con soporte para ficheros 
      mayores de 2GB en los sistemas Unix modernos de 32-bits. También el soporte
      para el manejo de cuerpos de respuesta &gt;2GB ha sido añadido.</dd>

      <dt>Eventos MPM</dt>
      <dd>El módulo <module>event</module> MPM usa un hilo separado para el manejo
      de las peticiones Keep Alive y aceptar las conexiones. Las peticiones de 
      Keep Alive tradicionalmente han requerido un "worker" de httpd para su manejo.
      Este "worker" dedicado no puede ser utilizado otra vez hasta que el Keep Alive
      haya expirado su tiempo de conexión. 
      </dd>

      <dt>Soporte de Base de Datos SQL</dt>
      <dd>El módulo <module>mod_dbd</module>, junto con el framework
      <code>apr_dbd</code>, nos trae soporte directo de SQL para los módulos
      que lo necesitan. Es compatible con la agrupación de conexiones 
      en procesos MPM.</dd>

    </dl>
  </section>

  <section id="module">
    <title>Mejoras en Módulos</title>
    <dl>
      <dt>Autenticación y Autorización</dt>
      <dd>Los módulos en el directorio aaa se han renombrado y ofrecen mejor 
	      soporte para la autenticación implícita (digest).
	      Por ejemplo: 
	      <code>mod_auth</code> se ha dividido ahora en
	      <module>mod_auth_basic</module> y
	      <module>mod_authn_file</module>; <code>mod_auth_dbm</code> ahora
	      se llama <module>mod_authn_dbm</module>; <code>mod_access</code> ha 
	      sido renombrado a <module>mod_authz_host</module>. También hay un nuevo 
	      módulo mod_authn_alias( ya eliminado en las versiones 2.3/2.4) para 
	      simplificar algunas configuraciones de autenticación.
      </dd>

      <dt><module outdated="true">mod_authnz_ldap</module></dt>
      <dd>Este módulo se ha traído de la versión 2.0 del módulo
          <code>mod_auth_ldap</code> a la versión 2.2 del framework de 
          <code>Autenticación/Autorización</code>. Las nuevas características 
          incluyen el uso de  valores de LDAP y filtros de búsqueda complejos 
          para la directiva 
          <directive module="mod_authz_core">Require</directive>.</dd>

      <dt><module>mod_authz_owner</module></dt>
      <dd>Un nuevo módulo que autoriza el acceso a ficheros basándose en el 
      	propietario del fichero en el sistema operativo.
      </dd>

      <dt><module>mod_version</module></dt>
      <dd>Este nuevo módulo permite que se habiliten bloques de configuración  
      	dependiendo de la versión del servidor.
      </dd>

      <dt><module>mod_info</module></dt>
      <dd>Se ha añadido un nuevo argumento al <code>config</code> que muestra
      las configuraciones de las directivas que se le pasan a Apache, incluyendo
      los nombres de los ficheros y en que linea se encuentra dicha configuración.
      Este módulo además muestra en orden todas las peticiones de hooks y información 
      adicional a la hora de compilar, similar a <code>httpd -V</code>.</dd>

      <dt><module>mod_ssl</module></dt>
      <!-- Need Info on SSLEngine Support? -->
      <dd>Se ha añadido soporte para el 
         <a href="http://www.ietf.org/rfc/rfc2817.txt">RFC 2817</a>, que permite
         conexiones para que se actualicen de texto plano al cifrado TLS.</dd>

      <dt><module>mod_imagemap</module></dt>
      <dd><code>mod_imap</code> Se ha renombrado a 
          <module>mod_imagemap</module> para evitar confusión en el usuario.
      </dd>
    </dl>

  </section>

  <section id="programs">
    <title>Mejoras de Programas</title>
    <dl>
      <dt><program>httpd</program></dt>
      <dd>Se ha añadido una nueva opción en la línea de comandos <code>-M</code>,
      dicha opción lista todos los módulos que se cargan basándose en la 
      configuración actual. A diferencia de la opción <code>-l</code>, esta lista
      incluye los DSOs cargados mediante el módulo<module>mod_so</module>.
  	  </dd>

      <dt><program>httxt2dbm</program></dt>
      <dd>Un nuevo programa para generar archivos dbm desde archivos de texto 
      	como entrada, para su uso en
        <directive module="mod_rewrite">RewriteMap</directive>
          con el mapa de tipo <code>dbm</code>.</dd>
    </dl>
  </section>

  <section id="developer">
    <title>Cambios para desarrolladores de Módulos</title>
    <dl>
      <dt><glossary>APR</glossary> 1.0 API</dt>

      <dd>Apache 2.2 usa la API de APR. Todas las funciones  y símbolos obsoletas
      se han eliminado de <code>APR</code> y
          <code>APR-Util</code>. Para mas detalles sobre dichos cambios
          vaya a la 
          <a href="http://apr.apache.org/">página de APR</a>.</dd>

      <dt>Autenticación y Autorización</dt>
      <dd>El paquete de módulos de autenticación y autorización se han renombrado 
          como se muestra en las siguientes líneas:
          <ul>
          <li><code>mod_auth_*</code>  -> Módulos que implementan un mecanismo de 
          autenticación por HTTP.</li>
          <li><code>mod_authn_*</code> -> Módulos que proporcionan un backend
           proveedor de autenticación.</li>
          <li><code>mod_authz_*</code> -> Módulos que implementan autorización 
          (o acceso)</li>
          <li><code>mod_authnz_*</code> -> Módulo que implementa ambas opciones
          autenticación &amp; autorización</li>
          </ul>
          Hay un nuevo esquema de proveedor de la autenticación en el backend 
          lo que facilita en gran medida la construcción de nuevos motores 
          de autenticación.
          </dd>

      <dt>Registro de errores de Conexión</dt>

      <dd>Una nueva función <code>ap_log_cerror</code> ha sido añadida para 
      registrar los errores que ocurren en la conexión del cliente. Cuando se
      registra el error, el mensaje incluye la dirección IP del cliente.</dd>

      <dt>Añadido Hooks para la configuración de Test</dt>

      <dd>Un nuevo hook, <code>test_config</code> se ha añadido para ayudar a 
      los módulos que necesitan ejecutar sólo código especial cuando el usuario 
      pasa como parámetro <code>-t</code> a <program>httpd</program>.</dd>

      <dt>Configuración de tamaño de pila para los procesos MPM's</dt>

      <dd>Una nueva directiva, <directive module="mpm_common"
          >ThreadStackSize</directive> se ha añadido para configurar 
          el tamaño de la pila de  todos los hilos de MPMs. Esta directiva
          es requerida por algún módulo de terceros en plataformas que tienen
          por defecto una pila con un tamaño pequeño.</dd>

      <dt>Manejo de protocolo para los filtros de salida</dt>

      <dd>En el pasado, cada filtro ha sido responsable de garantizar
       que genera las cabeceras de respuesta correctas donde les afecta.  
       Los filtros ahora delegan la administración común del protocolo
       a los módulos 
       <module>mod_filter</module>, usando llamadas a
       <code>ap_register_output_filter_protocol</code> ó
       <code>ap_filter_protocol</code>.</dd>

      <dt>Monitor de hooks añadido</dt>
      <dd>Monitor hook habilita a los módulos a ejecutar tareas regulares
        o programadas en el proceso padre (raíz).</dd>

      <dt>Cambio de expresiones regulares en la API</dt>

      <dd>La cabecera <code>pcreposix.h</code> ya no esta disponible;
      se ha cambiado por la nueva <code>ap_regex.h</code>. La 
      implementación POSIX.2 de <code>regex.h</code> expuesta por la cabecera 
      antigua, está ahora disponible en el espacio de nombre con <code>ap_</code>
      en la cabecera <code>ap_regex.h</code>. llama a <code>regcomp</code>,
      <code>regexec</code> y así sucesivamente pueden ser sustituidos por 
      llamadas a <code>ap_regcomp</code>, <code>ap_regexec</code>.</dd>

      <dt>DBD Framework (API de base de datos SQL)</dt>

      <dd><p>Con Apache 1.x y 2.0, algunos módulos que requieren un 
      	backend de SQL deben tomar la responsabilidad de gestionar por sí 
      	mismos. Aparte de reinventar la rueda, esto puede llegar a ser
      	ineficiente, por ejemplo cuando varios módulos cada uno mantiene su propia conexión.
      	</p>

      <p>Las versiones de Apache posteriores a la 2.1 proporciona la API de <code>ap_dbd</code> 
      para el manejo de las conexiones a las bases de datos (incluyendo estrategia 
      optimizadas para los hilos o no de MPMs), mientras que las versiones de 
      APR 1.2 y posteriores proporciona la API <code>apr_dbd</code> para 
      interactuar con la base de datos.</p>

      <p>Los nuevos módulos DEBEN usar estas APIs para todas las operaciones en 
      	bases de datos SQL. Aplicaciones existentes DEBEN ser actualizadas para 
      	que lo usen cuando sea posible, de forma transparente o como opción recomendada
      	para sus usuarios.</p>
      </dd>
    </dl>
  </section>
</manualpage>