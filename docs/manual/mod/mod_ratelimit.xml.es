<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1938788 -->
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

<modulesynopsis metafile="mod_ratelimit.xml.meta">
<name>mod_ratelimit</name>
<description>Limitación del ancho de banda para los clientes</description>
<status>Extension</status>
<sourcefile>mod_ratelimit.c</sourcefile>
<identifier>ratelimit_module</identifier>
<compatibility>
    <code>rate-initial-burst</code> disponible en httpd 2.4.24 y posteriores.
    La limitación de velocidad para contenido proxied no funciona correctamente hasta httpd 2.4.33.
</compatibility>

<summary>

<p>Proporciona un filtro llamado <code>RATE_LIMIT</code> para limitar el ancho de banda del cliente.
La limitación se aplica a cada respuesta HTTP mientras se transfiere al cliente,
y no se agrega a nivel de IP/cliente.
La velocidad de conexión que se va a simular se especifica, en KiB/s, mediante la
variable de entorno <code>rate-limit</code>.</p>

<p>Opcionalmente, se puede configurar una cantidad inicial de datos en modo
ráfaga, en KiB, que se transmitirá a velocidad completa antes de aplicar
la limitación a la velocidad especificada. Este valor es opcional y se establece
mediante la variable de entorno <code>rate-initial-burst</code>.</p>

<note type="warning"><title>Consumo de recursos</title>
<p>La limitación de velocidad se implementa suspendiendo la ejecución entre escrituras al cliente,
por lo que cada respuesta con limitación de velocidad ocupa un hilo (o proceso) del servidor durante
toda la duración, deliberadamente prolongada, de la transferencia. Esto se aplica
a todos los MPM, incluido <module>event</module>. Un número modesto de descargas lentas y
limitadas en velocidad puede agotar los workers disponibles del servidor e
impedir que se atiendan otras peticiones. Use este módulo con precaución,
límitelo a los recursos que lo necesiten, y ajuste el tamaño de
<directive module="mpm_common">MaxRequestWorkers</directive> en consecuencia.</p>
</note>

<example><title>Ejemplo de configuración</title>
<highlight language="config">
&lt;Location "/downloads"&gt;
    SetOutputFilter RATE_LIMIT
    SetEnv rate-limit 400
    SetEnv rate-initial-burst 512
&lt;/Location&gt;
</highlight>

<note type="warning">
Si el valor especificado para <code>rate-limit</code> provoca un desbordamiento de enteros, la limitación de velocidad se desactivará.
Si el valor especificado para <code>rate-limit-burst</code> provoca un desbordamiento de enteros, la ráfaga se desactivará.
</note>

</example>

</summary>

</modulesynopsis>
