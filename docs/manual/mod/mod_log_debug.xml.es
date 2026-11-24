<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1879077 -->
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

<modulesynopsis metafile="mod_log_debug.xml.meta">

<name>mod_log_debug</name>
<description>Registro de depuración configurable adicional</description>
<status>Experimental</status>
<sourcefile>mod_log_debug.c</sourcefile>
<identifier>log_debug_module</identifier>
<compatibility>Disponible en Apache 2.3.14 y posteriores</compatibility>

<section id="examples"><title>Ejemplos</title>

    <ol>
      <li>
        Registrar un mensaje tras procesar una petición a /foo/*:

        <highlight language="config">
&lt;Location "/foo/"&gt;
&nbsp;&nbsp;LogMessage "/foo/ has been requested"
&lt;/Location&gt;
        </highlight>
      </li>

      <li>
        Registrar un mensaje si la petición a /foo/* se procesa en una subpetición:
        <highlight language="config">
&lt;Location "/foo/"&gt;
&nbsp;&nbsp;LogMessage "subrequest to /foo/" hook=type_checker "expr=-T %{IS_SUBREQ}"
&lt;/Location&gt;
        </highlight>

        El hook log_transaction por defecto no se ejecuta para las subpeticiones,
        por lo que hay que usar un hook distinto.
      </li>


      <li>
        Registrar un mensaje si un cliente IPv6 provoca un timeout de la petición:
        <highlight language="config">
            LogMessage "IPv6 timeout from %{REMOTE_ADDR}" "expr=-T %{IPV6} &amp;&amp; %{REQUEST_STATUS} = 408"
        </highlight>
        Observe cómo se colocan las comillas dobles para el argumento <code>expr=</code>.
      </li>

      <li>
        Registrar el valor de la variable de entorno de petición "X-Foo" en cada
        fase de la petición:
        <highlight language="config">
&lt;Location "/"&gt;
&nbsp;&nbsp;LogMessage "%{reqenv:X-Foo}" hook=all
&lt;/Location&gt;
        </highlight>
        Junto con las marcas de tiempo en microsegundos del log de errores,
        <code>hook=all</code> también permite determinar el tiempo empleado
        en las distintas partes del procesamiento de la petición.
      </li>

    </ol>
</section>

<directivesynopsis>
<name>LogMessage</name>
<description>Registra un mensaje definido por el usuario en el log de errores
</description>
<syntax>LogMessage <var>message</var>
[hook=<var>hook</var>] [expr=<var>expression</var>]
</syntax>
<default>Unset</default>
<contextlist><context>directory</context>
</contextlist>

<usage>
    <p>Esta directiva hace que se registre en el log de errores un mensaje
    definido por el usuario. El mensaje puede usar variables y funciones de la
    <a href="../expr.html">sintaxis ap_expr</a>. Las referencias a cabeceras HTTP
    no provocarán que los nombres de las cabeceras se añadan a la cabecera Vary. Los
    mensajes se registran con el nivel de log info.</p>

    <p>El hook especifica antes de qué fase del procesamiento de la petición se
    registrará el mensaje. Se admiten los siguientes hooks:</p>

    <table border="1" style="zebra">
    <columnspec><column width="1"/></columnspec>
    <tr><th>Nombre</th></tr>
    <tr><td><code>pre_translate_name</code></td></tr>
    <tr><td><code>translate_name</code></td></tr>
    <tr><td><code>type_checker</code></td></tr>
    <tr><td><code>quick_handler</code></td></tr>
    <tr><td><code>map_to_storage</code></td></tr>
    <tr><td><code>check_access</code></td></tr>
    <tr><td><code>check_access_ex</code></td></tr>
    <tr><td><code>insert_filter</code></td></tr>
    <tr><td><code>check_authn</code></td></tr>
    <tr><td><code>check_authz</code></td></tr>
    <tr><td><code>fixups</code></td></tr>
    <tr><td><code>handler</code></td></tr>
    <tr><td><code>log_transaction</code></td></tr>
    </table>

    <p>El valor por defecto es <code>log_transaction</code>. También se admite
    el valor especial <code>all</code>, que hace que se registre un mensaje en cada
    fase. No todos los hooks se ejecutan en todas las peticiones.</p>

    <p>La expresión opcional permite restringir el mensaje si se cumple una
    condición. Los detalles de la sintaxis de la expresión se describen en
    la <a href="../expr.html">documentación de ap_expr</a>. Las referencias a cabeceras
    HTTP no provocarán que los nombres de las cabeceras se añadan a la cabecera Vary.</p>

</usage>

</directivesynopsis>

</modulesynopsis>
