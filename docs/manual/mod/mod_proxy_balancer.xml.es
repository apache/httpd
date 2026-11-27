<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933740 -->
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

<modulesynopsis metafile="mod_proxy_balancer.xml.meta">

<name>mod_proxy_balancer</name>
<description>Extensión de <module>mod_proxy</module> para balanceo de carga </description>
<status>Extension</status>
<sourcefile>mod_proxy_balancer.c</sourcefile>
<identifier>proxy_balancer_module</identifier>
<compatibility>Disponible en la versión 2.1 y posteriores</compatibility>

<summary>
    <p>Este módulo <em>requiere</em> los servicios de <module
    >mod_proxy</module> y proporciona balanceo de carga para
    todos los protocolos admitidos. Los más importantes son:</p>
    <ul>
        <li>HTTP, usando <module>mod_proxy_http</module></li>
        <li>FTP, usando <module>mod_proxy_ftp</module></li>
        <li>AJP13, usando <module>mod_proxy_ajp</module></li>
        <li>WebSocket, usando <module>mod_proxy_wstunnel</module></li>
    </ul>

    <p>El algoritmo planificador de balanceo de carga no lo proporciona este
    módulo, sino otros como:</p>
    <ul>
        <li><module>mod_lbmethod_byrequests</module></li>
        <li><module>mod_lbmethod_bytraffic</module></li>
        <li><module>mod_lbmethod_bybusyness</module></li>
        <li><module>mod_lbmethod_heartbeat</module></li>
    </ul>

    <p>Por lo tanto, para obtener la capacidad de balanceo de carga,
    <module>mod_proxy</module>, <module>mod_proxy_balancer</module>
    y al menos uno de los módulos de algoritmo planificador de balanceo de
    carga deben estar presentes en el servidor.</p>

    <note type="warning"><title>Advertencia</title>
      <p>No active el proxy hasta que haya <a
      href="mod_proxy.html#access">asegurado su servidor</a>. Los servidores
      proxy abiertos son peligrosos tanto para su red como para Internet en
      general.</p>
    </note>
</summary>
<seealso><module>mod_proxy</module></seealso>
<seealso><directive module="mod_proxy">BalancerMember</directive></seealso>
<seealso><directive module="mod_proxy">BalancerGrowth</directive></seealso>
<seealso><directive module="mod_proxy">BalancerPersist</directive></seealso>
<seealso><directive module="mod_proxy">BalancerInherit</directive></seealso>

<section id="scheduler">
    <title>Algoritmo planificador del balanceador de carga</title>
    <p>Actualmente, hay 4 algoritmos planificadores de balanceo de carga disponibles
    para usar: conteo de peticiones (<module>mod_lbmethod_byrequests</module>),
    conteo de tráfico ponderado (<module>mod_lbmethod_bytraffic</module>),
    conteo de peticiones pendientes (<module>mod_lbmethod_bybusyness</module>) y
    conteo de tráfico por heartbeat (<module>mod_lbmethod_heartbeat</module>).
    Estos se controlan mediante el valor <code>lbmethod</code> de
    la definición del Balancer. Vea la directiva <directive module="mod_proxy">ProxyPass</directive>
    para más información, especialmente sobre cómo
    configurar el Balancer y los BalancerMembers.</p>
</section>

<section id="stickiness">
    <title>Persistencia (stickiness) del balanceador de carga</title>
    <p>El balanceador admite persistencia (stickiness). Cuando una petición se
    envía por proxy a un backend, todas las peticiones siguientes del mismo
    usuario deberían enviarse por proxy al mismo backend. Muchos
    balanceadores de carga implementan esta función mediante una tabla que
    asocia direcciones IP de cliente a backends.
    Este enfoque es transparente para clientes y backends, pero sufre
    algunos problemas: distribución desigual de la carga si los propios
    clientes están ocultos detrás de proxies, errores de persistencia cuando
    un cliente usa una dirección IP dinámica que cambia durante una sesión, y
    pérdida de persistencia si la tabla de asociación se desborda.</p>
    <p>El módulo <module>mod_proxy_balancer</module> implementa la persistencia
    sobre dos medios alternativos: cookies y codificación de URL. El
    suministro de la cookie puede hacerlo bien el backend o bien el propio
    servidor web Apache. La codificación de URL normalmente se hace en el
    backend.</p>
</section>

<section id="example">
    <title>Ejemplos de configuración de un balanceador</title>
    <p>Antes de entrar en los detalles técnicos, aquí tiene un ejemplo de
    cómo podría usar <module>mod_proxy_balancer</module> para proporcionar
    balanceo de carga entre dos servidores backend:
    </p>

    <highlight language="config">
&lt;Proxy "balancer://mycluster"&gt;
    BalancerMember "http://192.168.1.50:80"
    BalancerMember "http://192.168.1.51:80"
&lt;/Proxy&gt;
ProxyPass        "/test" "balancer://mycluster"
ProxyPassReverse "/test" "balancer://mycluster"
    </highlight>

    <p>Otro ejemplo de cómo proporcionar balanceo de carga con persistencia
    usando <module>mod_headers</module>, incluso si el servidor backend
    no establece una cookie de sesión adecuada:
    </p>

    <highlight language="config">
Header add Set-Cookie "ROUTEID=.%{BALANCER_WORKER_ROUTE}e; path=/" env=BALANCER_ROUTE_CHANGED
&lt;Proxy "balancer://mycluster"&gt;
    BalancerMember "http://192.168.1.50:80" route=1
    BalancerMember "http://192.168.1.51:80" route=2
    ProxySet stickysession=ROUTEID
&lt;/Proxy&gt;
ProxyPass        "/test" "balancer://mycluster"
ProxyPassReverse "/test" "balancer://mycluster"
    </highlight>
</section>

<section id="environment">
    <title>Variables de entorno exportadas</title>
    <p>Actualmente hay 6 variables de entorno exportadas:</p>

    <dl>
    <!-- ============= BALANCER_SESSION_STICKY =============== -->
    <dt><var><a name="balancer_session_sticky" id="balancer_session_sticky">BALANCER_SESSION_STICKY</a></var></dt>
    <dd>
    <p>Se le asigna el valor de <var>stickysession</var> usado para la petición
    actual. Es el nombre de la cookie o parámetro de petición usado para las sesiones persistentes</p>
    </dd>

    <!-- ============= BALANCER_SESSION_ROUTE ================ -->
    <dt><var><a name="balancer_session_route" id="balancer_session_route">BALANCER_SESSION_ROUTE</a></var></dt>
    <dd>
    <p>Se le asigna la <var>route</var> extraída de la petición
    actual.</p>
    </dd>

    <!-- ============= BALANCER_NAME ========================= -->
    <dt><var><a name="balancer_name" id="balancer_name">BALANCER_NAME</a></var></dt>
    <dd>
    <p>Se le asigna el nombre del balanceador usado para la petición
    actual. El valor es algo como <code>balancer://foo</code>.</p>
    </dd>

    <!-- ============= BALANCER_WORKER_NAME ================== -->
    <dt><var><a name="balancer_worker_name" id="balancer_worker_name">BALANCER_WORKER_NAME</a></var></dt>
    <dd>
    <p>Se le asigna el nombre del worker usado para la petición actual.
    El valor es algo como <code>http://hostA:1234</code>.</p>
    </dd>

    <!-- ============= BALANCER_WORKER_ROUTE ================= -->
    <dt><var><a name="balancer_worker_route" id="balancer_worker_route">BALANCER_WORKER_ROUTE</a></var></dt>
    <dd>
    <p>Se le asigna la <var>route</var> del worker que se
    usará para la petición actual.</p>
    </dd>

    <!-- ============= BALANCER_ROUTE_CHANGED ================= -->
    <dt><var><a name="balancer_route_changed" id="balancer_route_changed">BALANCER_ROUTE_CHANGED</a></var></dt>
    <dd>
    <p>Se establece a 1 si la route de la sesión no coincide con la
    route del worker (BALANCER_SESSION_ROUTE != BALANCER_WORKER_ROUTE) o la
    sesión todavía no tiene una route establecida. Esto puede usarse para
    determinar cuándo/si es necesario enviar al cliente una route
    actualizada cuando se usan sesiones persistentes.</p>
    </dd>
    </dl>

</section>

<section id="balancer_manager">
    <title>Activar el soporte del Balancer Manager</title>
    <p>Este módulo <em>requiere</em> los servicios de
    <module>mod_status</module>.
    El balancer manager permite la actualización dinámica de los miembros
    del balanceador. Puede usar el balancer manager para cambiar el factor
    de balanceo de un miembro concreto, o para ponerlo en modo
    fuera de línea.
    </p>

    <p>Por lo tanto, para obtener la capacidad de gestión del balanceador de carga,
    <module>mod_status</module> y <module>mod_proxy_balancer</module>
    deben estar presentes en el servidor.</p>

    <p>Para activar la gestión del balanceador de carga para navegadores del
    dominio example.com añada este código a su archivo de configuración
    <code>httpd.conf</code></p>
<highlight language="config">
&lt;Location "/balancer-manager"&gt;
    SetHandler balancer-manager
    Require host example.com
&lt;/Location&gt;
</highlight>

    <p>Ahora puede acceder al balancer manager usando un navegador web
    para acceder a la página
    <code>http://your.server.name/balancer-manager</code>. Tenga en cuenta
    que solo los Balancers definidos fuera de contenedores <code>&lt;Location ...&gt;</code>
    pueden controlarse dinámicamente desde el Manager.</p>
</section>

<section id="stickiness_implementation">
    <title>Detalles sobre la persistencia del balanceador de carga</title>
    <p>Cuando se usa persistencia basada en cookies, es necesario configurar el
    nombre de la cookie que contiene la información sobre qué backend
    usar. Esto se hace mediante el atributo <var>stickysession</var> añadido
    a <directive module="mod_proxy">ProxyPass</directive> o
    <directive module="mod_proxy">ProxySet</directive>. El nombre de
    la cookie distingue mayúsculas y minúsculas. El balanceador extrae el valor de la
    cookie y busca un worker miembro con <var>route</var> igual
    a ese valor. La <var>route</var> también debe establecerse en
    <directive module="mod_proxy">ProxyPass</directive> o
    <directive module="mod_proxy">ProxySet</directive>. La cookie puede
    establecerla el backend, o, como se muestra en el
    <a href="#example">ejemplo</a> anterior, el propio servidor web Apache.</p>
    <p>Algunos backends usan una forma ligeramente distinta de cookie de
    persistencia, por ejemplo Apache Tomcat. Tomcat añade el nombre de la
    instancia de Tomcat al final de su cookie de id de sesión, separado con
    un punto (<code>.</code>) del id de sesión. Así, si el servidor web
    Apache encuentra un punto en el valor de la cookie de persistencia, solo
    usa la parte posterior al punto para buscar la route. Para que Tomcat
    conozca el nombre de su instancia, es necesario establecer el atributo
    <code>jvmRoute</code> dentro del archivo de configuración de Tomcat
    <code>conf/server.xml</code> al valor de la
    <var>route</var> del worker que conecta con el Tomcat correspondiente.
    El nombre de la cookie de sesión usada por Tomcat (y, de forma más
    general, por las aplicaciones web Java basadas en servlets) es
    <code>JSESSIONID</code>
    (en mayúsculas) pero puede configurarse para usar otro nombre.</p>
    <p>La segunda forma de implementar la persistencia es la codificación de URL.
    El servidor web busca un parámetro de consulta en la URL de la petición.
    El nombre del parámetro se especifica de nuevo usando <var>stickysession</var>.
    El valor del parámetro se usa para buscar un worker miembro con <var>route</var>
    igual a ese valor. Dado que no es fácil extraer y manipular todos los
    enlaces de URL contenidos en las respuestas, generalmente el trabajo de
    añadir los parámetros a cada enlace lo hace el backend que genera el
    contenido.
    En algunos casos podría ser viable hacer
    esto a través del servidor web usando <module>mod_substitute</module> o
    <module>mod_sed</module>. Sin embargo, esto puede tener un impacto negativo en el rendimiento.</p>
    <p>Los estándares de Java implementan la codificación de URL de forma algo
    distinta. Usan información de ruta (path info) añadida a la URL usando
    un punto y coma (<code>;</code>)
    como separador, y añaden el id de sesión a continuación. Como en el caso
    de la cookie, Apache Tomcat puede incluir el <code>jvmRoute</code>
    configurado en esta path info. Para que Apache encuentre este tipo de
    path info, es necesario establecer
    <code>scolonpathdelim</code> a <code>On</code> en
    <directive module="mod_proxy">ProxyPass</directive> o
    <directive module="mod_proxy">ProxySet</directive>.</p>
    <p>Por último, puede admitir cookies y codificación de URL al mismo tiempo,
    configurando el nombre de la cookie y el nombre del parámetro de URL
    separados por una barra vertical (<code>|</code>) como en el siguiente ejemplo:</p>
    <highlight language="config">
ProxyPass "/test" "balancer://mycluster" stickysession=JSESSIONID|jsessionid scolonpathdelim=On
&lt;Proxy "balancer://mycluster"&gt;
    BalancerMember "http://192.168.1.50:80" route=node1
    BalancerMember "http://192.168.1.51:80" route=node2
&lt;/Proxy&gt;
    </highlight>
    <p>Si tanto la cookie como el parámetro de petición proporcionan información
    de enrutamiento para la misma petición, se usa la información del parámetro de petición.</p>
</section>

<section id="stickiness_troubleshooting">
    <title>Solución de problemas de persistencia del balanceador de carga</title>
    <p>Si experimenta errores de persistencia, por ejemplo que los usuarios
    pierden sus sesiones de aplicación y necesitan volver a iniciar sesión,
    primero debería comprobar si esto se debe a que los backends a veces no
    están disponibles, o si su configuración es incorrecta. Para averiguar
    posibles problemas de estabilidad con los backends, revise su log de
    errores de Apache en busca de mensajes de error de proxy.</p>
    <p>Para verificar su configuración, primero compruebe si la persistencia
    se basa en una cookie o en codificación de URL. El siguiente paso sería
    registrar los datos apropiados en el log de acceso usando un
    <directive module="mod_log_config">LogFormat</directive> ampliado.
    Los siguientes campos son útiles:</p>
    <dl>
    <dt><code>%{MYCOOKIE}C</code></dt>
    <dd>El valor contenido en la cookie con nombre <code>MYCOOKIE</code>.
    El nombre debería ser el mismo que se indica en el atributo
    <var>stickysession</var>.</dd>
    <dt><code>%{Set-Cookie}o</code></dt>
    <dd>Esto registra cualquier cookie establecida por el backend. Puede
    rastrear si el backend establece la cookie de sesión que espera, y
    con qué valor.</dd>
    <dt><code>%{BALANCER_SESSION_STICKY}e</code></dt>
    <dd>El nombre de la cookie o parámetro de petición usado
    para buscar la información de enrutamiento.</dd>
    <dt><code>%{BALANCER_SESSION_ROUTE}e</code></dt>
    <dd>La información de route encontrada en la petición.</dd>
    <dt><code>%{BALANCER_WORKER_ROUTE}e</code></dt>
    <dd>La route del worker elegido.</dd>
    <dt><code>%{BALANCER_ROUTE_CHANGED}e</code></dt>
    <dd>Se establece a <code>1</code> si la route de la petición
    es distinta de la route del worker, es decir,
    la petición no pudo tratarse con persistencia.</dd>
    </dl>
    <p>Las razones habituales de la pérdida de sesión son los tiempos de
    espera de sesión, que normalmente son configurables en el servidor
    backend.</p>
    <p>El balanceador también registra información detallada sobre el
    tratamiento de la persistencia en el log de errores, si el nivel de
    log se establece en <code>debug</code> o superior. Esta es una forma
    sencilla de diagnosticar problemas de persistencia, pero el volumen de
    log podría ser demasiado alto para servidores en producción con
    carga alta.</p>
</section>

</modulesynopsis>
