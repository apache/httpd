<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1935407 -->
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

<modulesynopsis metafile="mpm_winnt.xml.meta">

<name>mpm_winnt</name>
<description>Módulo multiproceso optimizado para Windows NT.</description>
<status>MPM</status>
<sourcefile>mpm_winnt.c</sourcefile>
<identifier>mpm_winnt_module</identifier>

<summary>
    <p>Este módulo multiproceso (MPM) es el predeterminado para los
    sistemas operativos Windows NT. Usa un único proceso de control
    que lanza un único proceso hijo, el cual a su vez crea
    hilos para atender las peticiones</p>

    <p>La capacidad se configura mediante la directiva
    <directive module="mpm_common">ThreadsPerChild</directive>,
    que establece el número máximo de conexiones de cliente concurrentes.</p>

    <p>Por defecto, este MPM usa APIs avanzadas de Windows para aceptar
    nuevas conexiones de cliente. En algunas configuraciones, productos
    de terceros pueden interferir con esta implementación, con los siguientes
    mensajes escritos en el log del servidor web:</p>

    <example>
        Child: Encountered too many AcceptEx faults accepting client connections.<br />
        winnt_mpm: falling back to 'AcceptFilter none'.
    </example>

    <p>El MPM recurre a una implementación más segura, pero algunas peticiones de cliente
    no se procesaron correctamente. Para evitar este error, use
    <directive module="core">AcceptFilter</directive> con el filtro de aceptación
    <code>none</code>.</p>

    <highlight language="config">
AcceptFilter http none
AcceptFilter https none
    </highlight>

    <p><em>En Apache httpd 2.0 y 2.2,
    <directive>Win32DisableAcceptEx</directive> se usaba para este propósito.</em></p>

    <p>El MPM WinNT se diferencia de los MPMs de Unix, como worker y event,
    en varios aspectos:</p>

    <ul>
      <li>Cuando un proceso hijo está terminando por un apagado, un reinicio, o
      <directive module="mpm_common">MaxConnectionsPerChild</directive>,
      las peticiones activas en el proceso que está terminando tienen
      <directive module="core">TimeOut</directive> segundos para finalizar antes
      de que se aborte el procesamiento. No se implementan otros tipos de reinicio y apagado.</li>

      <li>Los nuevos procesos hijo leen los archivos de configuración en lugar de
      heredar la configuración del padre. El comportamiento será el
      mismo que en Unix si el proceso hijo se crea al arrancar
      o reiniciar, pero si un proceso hijo se crea porque el anterior
      falló o alcanzó
      <directive module="mpm_common">MaxConnectionsPerChild</directive>,
      cualquier cambio pendiente en la configuración pasará a estar activo en el
      hijo en ese momento, y el padre y el hijo usarán una
      configuración distinta. Si se han implementado parcialmente cambios de
      configuración planificados y la configuración actual no se puede
      analizar, el proceso hijo de reemplazo no podrá arrancar y el servidor
      se detendrá. Debido a este comportamiento, los archivos de configuración no deberían
      cambiarse hasta el momento de un reinicio del servidor.</li>

      <li>Los hooks <code>monitor</code> y <code>fatal_exception</code>
      no están implementados actualmente.</li>

      <li><directive>AcceptFilter</directive> está implementado en el MPM
      y tiene un tipo de control distinto sobre la gestión de las nuevas conexiones.
      (Consulte la documentación de <directive module="core">AcceptFilter</directive>
      para más detalles.)</li>
    </ul>


</summary>

<seealso><a href="../mpm.html">Módulos multiproceso (MPMs)</a></seealso>
<seealso><a href="../platform/windows.html">Uso del servidor HTTP Apache en Microsoft Windows</a></seealso>

<directivesynopsis location="core"><name>AcceptFilter</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>CoreDumpDirectory</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>PidFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Listen</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ListenBacklog</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxConnectionsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxMemFree</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ScoreBoardFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ReceiveBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>SendBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadLimit</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadStackSize</name>
</directivesynopsis>

</modulesynopsis>
