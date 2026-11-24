<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1421821 -->
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

<modulesynopsis metafile="mod_dumpio.xml.meta">

<name>mod_dumpio</name>
<description>Vuelca toda la E/S en el registro de errores según se desee.</description>
<status>Extension</status>
<sourcefile>mod_dumpio.c</sourcefile>
<identifier>dumpio_module</identifier>

<summary>
    <p><code>mod_dumpio</code> permite registrar (volcar)
    en el archivo error.log toda la entrada recibida por Apache y/o
    toda la salida enviada por Apache.
    </p>

    <p>El volcado de datos se realiza justo después del descifrado SSL (para
    la entrada) y justo antes del cifrado SSL (para la salida). Como es
    de esperar, esto puede producir volúmenes de datos extremos,
    y solo debería usarse al depurar problemas.</p>
</summary>

<section id="enable">
    <title>Activar el soporte de dumpio</title>

    <p>Para activar el módulo, debe compilarse y cargarse
    en su configuración de Apache en ejecución. El registro puede
    activarse o desactivarse por separado para la entrada y la salida mediante
    las directivas siguientes. Además, <module>mod_dumpio</module>
    debe configurarse con <directive
    module="core">LogLevel</directive> <code>trace7</code>:
    </p>
    <highlight language="config">
      LogLevel dumpio:trace7
    </highlight>
</section>

<directivesynopsis>

<name>DumpIOInput</name>
<description>Vuelca todos los datos de entrada en el registro de errores</description>
<syntax>DumpIOInput On|Off</syntax>
<default>DumpIOInput Off</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Activa el volcado de toda la entrada.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      DumpIOInput On
      </highlight>
    </example>
</usage>

</directivesynopsis>

<directivesynopsis>

<name>DumpIOOutput</name>
<description>Vuelca todos los datos de salida en el registro de errores</description>
<syntax>DumpIOOutput On|Off</syntax>
<default>DumpIOOutput Off</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Activa el volcado de toda la salida.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      DumpIOOutput On
      </highlight>
    </example>
</usage>

</directivesynopsis>

</modulesynopsis>
