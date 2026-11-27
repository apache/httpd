<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1437838 -->
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

<modulesynopsis metafile="mod_heartbeat.xml.meta">

<name>mod_heartbeat</name>
<description>Envía mensajes con el estado del servidor al proxy de frontend</description>
<status>Experimental</status>
<sourcefile>mod_heartbeat</sourcefile>
<identifier>heartbeat_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
<p> <module>mod_heartbeat</module> envía mensajes multicast a un listener de <module>mod_heartmonitor</module>
que anuncia el recuento actual de conexiones del servidor. Normalmente, <module>mod_heartmonitor</module>
se ejecutará en un servidor proxy con <module>mod_lbmethod_heartbeat</module> cargado, lo que permite
que <directive module="mod_proxy">ProxyPass</directive> use el <em>lbmethod</em> "heartbeat" dentro
de <directive module="mod_proxy">ProxyPass</directive>.</p>
<p>
    <module>mod_heartbeat</module> en sí se carga en los servidores de origen que atienden peticiones
    a través de los servidores proxy.
</p>

    <note type="warning">
        Para usar <module>mod_heartbeat</module>,
        <module>mod_status</module> y <module>mod_watchdog</module>
        deben ser módulos estáticos o, si son módulos dinámicos, deben
        cargarse antes de <module>mod_heartbeat</module>.
    </note>

</summary>

<section id="consuming">
    <title>Consumir la salida de mod_heartbeat</title>
  <p>
      Cada 1 segundo, este módulo genera un único paquete UDP
      multicast, que contiene el número de workers ocupados e inactivos. El
      paquete tiene un formato ASCII simple, similar a los parámetros de consulta GET
      en HTTP.
  </p>

<example><title>Un paquete de ejemplo</title>
v=1&amp;ready=75&amp;busy=0
</example>

  <p>
    Los consumidores deben estar preparados para gestionar nuevas variables además de busy y ready,
    separadas por '&amp;', que puedan añadirse en el futuro.
  </p>

</section>

<directivesynopsis>
<name>HeartbeatAddress</name>
<description>Dirección multicast para los paquetes heartbeat</description>
<syntax>HeartbeatAddress <var>addr:port</var></syntax>
<default>disabled</default>
<contextlist><context>server config</context></contextlist>

<usage>
<p>La directiva <directive>HeartbeatAddress</directive> especifica la
dirección multicast a la que <module>mod_heartbeat</module> enviará
información de estado. Esta dirección normalmente corresponderá a un
<directive module="mod_heartmonitor">HeartbeatListen</directive> configurado en un
sistema proxy de frontend.</p>
<highlight language="config">
HeartbeatAddress 239.0.0.1:27999
</highlight>
</usage>
</directivesynopsis>

</modulesynopsis>
