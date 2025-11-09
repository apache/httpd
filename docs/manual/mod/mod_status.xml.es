<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.en.xsl"?>
<!-- English Revision: 1755973:1873230 (outdated) -->
<!-- Spanish Translation: Daniel Ferradal <dferradal@apache.org> -->


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

<modulesynopsis metafile="mod_status.xml.meta">

<name>mod_status</name>
<description>Provee información de la actividad y rendimiento del 
  servidor</description>
<status>Base</status>
<sourcefile>mod_status.c</sourcefile>
<identifier>status_module</identifier>


<summary>
    <p>El módulo de Estado permite a un administrador averiguar lo bien que está
    rindiendo su servidor. Se presenta una página HTML que da las estadísticas
    actuales del servidor en una forma fácilmente legible. Si es necesario
    se puede hacer que ésta página se refresque automáticamente (con un navegador
    compatible). También hay otra página que da una sencilla lista legible por 
    máquina del estado actual del servidor.</p>

    <p>Los detalles que se dan son:</p>

    <ul>
      <li>El número de worker sirviendo peticiones</li>

      <li>El número de worker desocupado</li>

      <li>El estado de cada worker, el número de peticiones que ese worker ha
      realizado y el número total de bytes servido por el worker (*)</li>

      <li>Un número total de accesos y recuento de bytes servidos (*)</li>

      <li>La hora a la que el servidor ha sido arrancado/reiniciado y el tiempo
      que se ha estado ejecutando</li>

      <li>Medias indicando el número de peticiones por segundo, el número de bytes
      servido por segundo y la media de bytes por petición (*)</li>

      <li>El porcentaje actual de CPU usado por cada worker y en total por todos
      los workers al completo (*)</li>

      <li>Los hosts actuales y peticiones que se están procesando en el momento
       (*)</li>
    </ul>

    <p>Las líneas marcadas con "(*)" solo están disponibles si
    <directive module="core">ExtendedStatus</directive> está configurado a
    <code>On</code>.  En la versión 2.3.6, cargar mod_status pondrá
    <directive module="core">ExtendedStatus</directive> en On por defecto.</p>

    <note>
      <strong>Debería tenerse en cuenta que si se carga 
      <module>mod_status</module> en el servidor, su handler estará disponible
      en <em>todos</em> los ficheros de configuración, incluidos ficheros
      <em>de</em>-directorio (<em>p. ej.</em>, <code>.htaccess</code>). Esto puede tener ramificaciones relacionadas con la seguridad en su sitio web.</strong>
    </note>

</summary>

<section id="enable">
    <title>Activando el Soporte de Estado</title>

    <p>Para activar los reportes de estado para navegadores tán solo desde el 
    dominio example.com añada este código en su fichero de configuración 
    <code>httpd.conf</code></p>
<highlight language="config">
&lt;Location "/server-status"&gt;
    SetHandler server-status
    Require host example.com
&lt;/Location&gt;
</highlight>

    <p>Ahora puede acceder a estadísticas del servidor usando un navegador web
    para acceder a la página
    <code>http://your.server.name/server-status</code></p>
</section>

<section id="autoupdate">

    <title>Actualizaciones Automáticas</title>
    <p>Puede hacer que la página de estado se actualice automáticamente si tiene
    un navegador que soporte "refresh". Acceda a la página
    <code>http://your.server.name/server-status?refresh=N</code> para refrescar
    la página cada N segundos.</p>

</section>

<section id="machinereadable">

    <title>Fichero de Estado legible por máquina</title>
    <p>Una versión legible por máquina del fichero de estado está disponible
    accediendo a la página 
    <code>http://your.server.name/server-status?auto</code>. Esto es útil cuando
    la solicitud de estado se lanza automáticamente, vea el programa Perl 
    <code>log_server_status</code>, que encontrará en el directorio 
    <code>/support</code> de su instalación del Servidor Apache HTTP.</p>

</section>

<section id="troubleshoot">
    <title>Usando server-status para identificar problemas</title>

    <p>La página <code>server-status</code> puede usarse como un lugar donde
    empezar a identificar problemas en una situación en la que su servidor está
    consumiento todos los recursos disponibles (CPU o memoria), y ustéd desea
    identificar qué peticiones o clientes están causando el problema.</p>

    <p>Primero, asegúrese de que tiene <directive
    module="core">ExtendedStatus</directive> configurado a on, de manera que 
    puede ver toda la información de la petición y el cliente para cada proceso
    o hilo.</p>

    <p>Ahora mire en la lista de procesos (usando <code>top</code>, o utilidad
    similar para ver procesos) para identificar los procesos específicos
    que son los principales culpables. Ordene la salida de <code>top</code> por
    uso de CPU, o de memoria, dependiendo del problema que esté intentando 
    ubicar.</p>

    <p>Recargue la página <code>server-status</code>, y busque esos ids de
    proceso, y podrá ver qué petición se está sirviendo por ese proceso y para
    qué cliente. Las peticiones son pasajeras, así que puede que necesite
    intentarlo varias veces antes de que lo cace en el acto, por decirlo de 
    alguna manera.</p>

    <p>Este proceso <em>debería</em> darle alguna idea de qué cliente, o qué
    tipo de petición, son los principales responsables para sus problemas de
    carga. A menudo identificará una aplicación web en particular que puede 
    estar comportándose como no es debido, o un cliente en particular que está
    atacando su sitio web.</p>

</section>

</modulesynopsis>
