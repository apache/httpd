<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 151408:421100 (outdated) -->

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

<modulesynopsis metafile="beos.xml.meta">

<name>beos</name>
<description>Este m&#243;dulo de muiltiprocesamiento est&#225;
optimizado para BeOS.</description>
<status>MPM</status>
<sourcefile>beos.c</sourcefile>
<identifier>mpm_beos_module</identifier>

<summary>
    <p>Este m&#243;dulo de muiltiprocesamiento (MMP)
      es el que usa por defecto para BeOS. Usa un
      &#250;nico proceso de control que crea hebras para atender las
      peticiones.</p>
</summary>
<seealso><a href="../bind.html">Configurar las direcciones y los
puertos que usa Apache</a></seealso>

<directivesynopsis location="mpm_common"><name>User</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Group</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Listen</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ListenBacklog</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>SendBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>StartThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MinSpareThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxSpareThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxClients</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>CoreDumpDirectory</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxMemFree</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>PidFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ScoreBoardFile</name>
</directivesynopsis>

<directivesynopsis>
<name>MaxRequestsPerThread</name>
<description>Limita el n&#250;mero de peticiones que una hebra (thread) puede
atender durante su vida</description>
<syntax>MaxRequestsPerThread <var>number</var></syntax>
<default>MaxRequestsPerThread 0</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>MaxRequestsPerThread</directive> fija
    el n&#250;mero m&#225;ximo de peticiones que una hebra del
    servidor puede atender durante su vida. Despues de atender
    <directive>MaxRequestsPerThread</directive> peticiones, la hebra
    termina. Si el l&#237;mite fijado en <directive
    >MaxRequestsPerThread</directive> es <code>0</code>, entonces la
    hebra puede atender peticiones indefinidamente.</p>

    <p>Fijar la directiva <directive>MaxRequestsPerThread</directive>
    a un l&#237;mite distinto de cero ofrece dos benefcios
    fundamentales:</p>

    <ul>
      <li>limita la cantidad de memoria que puede consumir una hebra
      si hay una filtraci&#243;n (accidental) de memoria;</li>

      <li>poniendo un l&#237;mite a la vida de las hebras, se ayuda a
      reducir el n&#250;mero de hebras cuando se reduce la carga de
      trabajo en el servidor.</li>
    </ul>

    <note><title>Nota:</title> <p>Para peticiones <directive
      module="core">KeepAlive</directive>, solo la primera
      petici&#243;n se tiene en cuenta para este l&#237;mite. De hecho, en este
      caso el l&#237;mite se impone sobre el n&#250;mero m&#225;ximo
      de <em>conexiones</em> por hebra.</p>
    </note>
</usage>
</directivesynopsis>

</modulesynopsis>


