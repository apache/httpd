<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1873915 -->
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

<modulesynopsis metafile="mod_cgid.xml.meta">

<name>mod_cgid</name>
<description>Ejecución de scripts CGI usando un
    daemon CGI externo</description>
<status>Base</status>
<sourcefile>mod_cgid.c</sourcefile>
<identifier>cgid_module</identifier>
<compatibility>Solo MPMs de Unix con hilos</compatibility>

<summary>
    <p>Salvo por las optimizaciones y la directiva adicional <directive
    module="mod_cgid">ScriptSock</directive> mencionada más abajo,
    <module>mod_cgid</module> se comporta de forma similar a <module>mod_cgi</module>.
    <strong>Consulte el resumen de <module>mod_cgi</module> para más detalles
    sobre Apache y CGI.</strong></p>

    <p>En ciertos sistemas operativos Unix, hacer un fork de un proceso desde un
    servidor multihilo es una operación muy costosa, porque el
    nuevo proceso replicará todos los hilos del proceso
    padre. Para evitar incurrir en este coste en cada invocación
    de CGI, <module>mod_cgid</module> crea un daemon externo que se
    encarga de hacer fork de los procesos hijo que ejecutan los scripts CGI. El
    servidor principal se comunica con este daemon usando un socket
    de dominio unix.</p>

    <p>Este módulo se usa por defecto en lugar de
    <module>mod_cgi</module> siempre que se seleccione un MPM multihilo
    durante el proceso de compilación. A nivel de usuario,
    este módulo es idéntico en configuración y funcionamiento a
    <module>mod_cgi</module>. La única excepción es la
    directiva adicional <code>ScriptSock</code>, que indica el
    nombre del socket a usar para la comunicación con el daemon
    de cgi.</p>
</summary>

<seealso><module>mod_cgi</module></seealso>
<seealso><a href="../suexec.html">Ejecución de programas CGI con distintos
    identificadores de usuario</a></seealso>

<directivesynopsis location="mod_cgi">
<name>ScriptLog</name>
</directivesynopsis>

<directivesynopsis location="mod_cgi">
<name>ScriptLogLength</name>
</directivesynopsis>

<directivesynopsis location="mod_cgi">
<name>ScriptLogBuffer</name>
</directivesynopsis>

<directivesynopsis>
<name>ScriptSock</name>
<description>El prefijo del nombre de archivo del socket a usar para la comunicación con
el daemon de cgi</description>
<syntax>ScriptSock <var>file-path</var></syntax>
<default>ScriptSock cgisock</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Esta directiva establece el prefijo del nombre de archivo del socket a usar para la
    comunicación con el daemon CGI; se añadirá una extensión correspondiente
    al ID de proceso del servidor. El socket se abrirá
    usando los permisos del usuario que inicia Apache (normalmente
    root). Para mantener la seguridad de las comunicaciones con los scripts
    CGI, es importante que ningún otro usuario tenga permiso para
    escribir en el directorio donde se encuentra el socket.</p>

    <p>Si <var>file-path</var> no es una ruta absoluta, la ubicación especificada
    será relativa al valor de
    <directive module="core">DefaultRuntimeDir</directive>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      ScriptSock /var/run/cgid.sock
    </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CGIDScriptTimeout</name>
<description>El tiempo de espera de más salida del
programa CGI</description>
<syntax>CGIDScriptTimeout <var>time</var>[s|ms]</syntax>
<default>el valor de la directiva <directive module="core">Timeout</directive> cuando
no está establecido o se ha establecido a 0</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<compatibility>Disponible en httpd 2.4.10 y posteriores; en versiones anteriores no se aplicaba ningún tiempo de espera</compatibility>

<usage>
    <p>Esta directiva limita el tiempo de espera de más salida del
    programa CGI. Si se supera ese tiempo, se terminan la petición y el CGI.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      CGIDScriptTimeout 20
    </highlight>
    </example>

</usage>
</directivesynopsis>

</modulesynopsis>
