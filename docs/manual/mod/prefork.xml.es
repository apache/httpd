<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.en.xsl"?>
<!-- English Revision: 1.8.2.7  -->

<!--
 Copyright 2004 The Apache Software Foundation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<modulesynopsis metafile="prefork.xml.meta">

<name>prefork</name>
<description>Implementa un servidor web pre-forking y no
hebrado</description>
<status>MPM</status>
<sourcefile>prefork.c</sourcefile>
<identifier>mpm_prefork_module</identifier>

<summary>
    <p>Este M&#243;dulo de MultiProcesamiento (MPM) implementa un
    servidor web pre-forking y no hebrado que trata las peticiones de
    una manera similar a como lo hac&#237;a Apache 1.3.  Esto es
    apropiado para sitios web que necesitan evitar el hebrado para ser
    compatibles con librer&#237;as que no son seguras cuado se usan
    hebras.  Es tambi&#233;n el mejor MPM para aislar cada
    petici&#243;n, de manera que si suge un problema con una
    petici&#243;n, esto no afecte al resto.</p>

    <p>Este MPM est&#225; muy autorregulado, de manera que muy pocas
    veces es necesario ajustar los valores de sus directivas de
    configuraci&#243;n. El valor que se fije en la directiva
    <directive module="mpm_common">MaxClients</directive> debe ser lo
    suficientemente grande para tratar tantas peticiones
    simult&#225;neas como espere recibir su sitio web, pero lo
    suficientemente peque&#241;o para asegurarse de que hay memoria
    RAM suficiente para todos los procesos.</p>
</summary>
<seealso><a href="../bind.html">Especificar las direcciones y los puertos
que usa Apache</a></seealso>

<section id="how-it-works"><title>C&#243;mo funciona</title> <p>Un
    solo proceso de control es el responsable de lanzar los procesos
    hijo que escuchan las peticiones que se puedan producir y las
    sirven cuando llegan. Apache siempre intenta mantener varios
    procesos <dfn>de sobra</dfn> o en espera, que est&#233;n
    disponibles para servir peticiones cuando lleguen. As&#237;, los
    clientes no tienen que esperar a que un nuevo proceso hijo sea
    creado para ser atendidos.</p>

    <p>Las directivas <directive
    module="mpm_common">StartServers</directive>, <directive
    module="prefork">MinSpareServers</directive>, <directive
    module="prefork">MaxSpareServers</directive>, y <directive
    module="mpm_common">MaxClients</directive> regulan la forma en que
    el proceso padre crea hijos para servir peticiones. En general,
    Apache funciona bien sin hacer muchas modificaciones en los
    valores por defecto de estas directivas, de manera que la mayor
    parte de los sitios web no necesitan ajustar esas directivas a
    valores diferentes. Los sitios web que necesiten servir m&#225;s
    de 256 peticiones simult&#225;neas pueden necesitar incrementar el
    valor de <directive module="mpm_common">MaxClients</directive>,
    mientras que los sitios web con memoria limitada pueden necesitar
    decrementar <directive module="mpm_common">MaxClients</directive>
    para evitar que el rendimiento del servidor se degrade (pasando
    los contenidos de memoria al disco y de vuelta a memoria). Puede
    obtener m&#225;s informaci&#243;n sobre como mejorar el
    rendimiento del proceso de creaci&#243;n de procesos en la
    documentaci&#243;n sobre <a href="../misc/perf-tuning.html">mejora
    del rendimiento</a>.</p>

    <p>El proceso padre de Apache se inicia normalmente como usuario
    <code>root</code> en Unix para que escuche en el puerto 80, sin
    embargo, los procesos hijo se crean con menores privilegios de
    usuario. Las directivas <directive
    module="mpm_common">User</directive> y <directive
    module="mpm_common">Group</directive> se usan para determinar los
    privilegios de los procesos hijo de Apache. Los procesos hijo
    deben ser capaces de leer todos los contenidos que van a servir,
    pero deben tener los menores privilegios posibles.</p>

    <p>La directiva <directive
    module="mpm_common">MaxRequestsPerChild</directive> controla
    c&#243;mo el servidor recicla frecuentemente los procesos
    eliminando los antiguos y creando nuevos.</p>
</section>

<directivesynopsis location="mpm_common"><name>BS2000Account</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>CoreDumpDirectory</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>EnableExceptionHook</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>PidFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Listen</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ListenBacklog</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>LockFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxClients</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxMemFree</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxRequestsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ScoreBoardFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>SendBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ServerLimit</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>StartServers</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>User</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Group</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>AcceptMutex</name>
</directivesynopsis>

<directivesynopsis>
<name>MaxSpareServers</name>
<description>N&#250;mero m&#225;ximo de procesos hijo en espera que
puede tener el servdor</description>
<syntax>MaxSpareServers <var>number</var></syntax>
<default>MaxSpareServers 10</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>MaxSpareServers</directive> determina
    el n&#250;mero m&#225;ximo de procesos hijo <em>en espera</em>
    deseado. Un proceso en espera es aquel que no est&#225; atendiendo
    ninguna petici&#243;n. Si hay m&#225;s de
    <directive>MaxSpareServers</directive> procesos hijo en espera,
    entonces el proceso padre elimina el exceso.</p>

    <p>Ajustar este par&#225;metro debe ser necesario solo en sitios
    web con muchas visitas. Fijar un valor alto para este
    par&#225;metro es una mala idea casi siempre. Si fija un valor por
    debajo de <directive module="prefork">MinSpareServers</directive>,
    Apache ajustar&#225; autom&#225;ticamente el valor a <directive
    >MinSpareServers</directive><code> + 1</code>.</p>
</usage>
<seealso><directive module="prefork">MinSpareServers</directive></seealso>
<seealso><directive module="mpm_common">StartServers</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>MinSpareServers</name>
<description>N&#250;mero m&#237;nimo de procesos hijo en espera</description>
<syntax>MinSpareServers <var>number</var></syntax>
<default>MinSpareServers 5</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>MinSpareServers</directive> fija el
    n&#250;mero m&#237;nimo de procesos hijo <em>en espera</em>. Un
    proceso en espera es aquel que no est&#225; atendiendo ninguna
    petici&#243;n. Si hay menos procesos hijo en espera que
    <directive>MinSpareServers</directive>, entonces el proceso padre
    crea nuevos procesos hijo a un ritmo m&#225;ximo de uno por
    segundo.</p>

    <p>Ajustar este par&#225;metro debe ser necesario solo en sitios
    web con muchas visitas. Fijar un valor alto para este
    par&#225;metro es una mala idea casi siempre.</p>
</usage>
<seealso><directive module="prefork">MaxSpareServers</directive></seealso>
<seealso><directive module="mpm_common">StartServers</directive></seealso>
</directivesynopsis>

</modulesynopsis>





