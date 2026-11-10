<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1731351 -->
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

<!--<modulesynopsis> is the root tag and must surround all other tags.
The sequence of tags is important and must be followed in order for
the document to validate. -->

<modulesynopsis metafile="mod_dialup.xml.meta">
<name>mod_dialup</name>
<description>Envía contenido estático con una limitación de ancho de banda, definida según los distintos estándares de los antiguos módems</description>
<status>Experimental</status>
<sourcefile>mod_dialup.c</sourcefile>
<identifier>dialup_module</identifier>

<summary>
<p>Es un módulo que envía contenido estático con una limitación de ancho de banda, definida
según los distintos estándares de los antiguos módems. Así, puede navegar por su sitio con un módem
V.92 de 56k, añadiendo algo como esto:</p>

<highlight language="config">
&lt;Location "/mysite"&gt;
    ModemStandard "V.92"
&lt;/Location&gt;
</highlight>

<p>Anteriormente, para limitar el ancho de banda, los módulos tenían que bloquear un hilo
completo, por cada cliente, e insertar esperas para ralentizar el ancho de banda.
Usando la nueva funcionalidad de suspensión, un manejador puede recibir una notificación N
milisegundos en el futuro, y será invocado por el MPM Event en un hilo distinto,
una vez que el temporizador se cumpla. A partir de ahí, el manejador puede continuar enviando datos al cliente.</p>
</summary>

<directivesynopsis>
<name>ModemStandard</name>
<description>Estándar de módem a simular</description>
<syntax>ModemStandard V.21|V.26bis|V.32|V.34|V.92</syntax>
<contextlist><context>directory</context></contextlist>

<usage>
<p>Especifique qué estándar de módem desea simular.</p>

<highlight language="config">
&lt;Location "/mysite"&gt;
    ModemStandard "V.26bis"
&lt;/Location&gt;
</highlight>

</usage>

</directivesynopsis>

</modulesynopsis>
