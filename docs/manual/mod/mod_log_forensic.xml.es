<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1343880 -->
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

<modulesynopsis metafile="mod_log_forensic.xml.meta">

<name>mod_log_forensic</name>
<description>Registro forense de las peticiones realizadas al servidor</description>
<status>Extension</status>
<sourcefile>mod_log_forensic.c</sourcefile>
<identifier>log_forensic_module</identifier>
<compatibility>Ya no es necesario <module>mod_unique_id</module> desde la
versión 2.1</compatibility>

<summary>
    <p>Este módulo permite el registro forense de las peticiones de los
    clientes. El registro se hace antes y después de procesar una petición,
    por lo que el log forense contiene dos líneas de registro por cada
    petición. El registrador forense es muy estricto, lo que significa que:</p>

    <ul>
    <li>El formato es fijo. No se puede modificar el formato de registro en
    tiempo de ejecución.</li>
    <li>Si no puede escribir sus datos, el proceso hijo
    termina inmediatamente y puede generar un volcado de núcleo (dependiendo de su
    configuración de <directive module="mpm_common">CoreDumpDirectory</directive>).</li>
    </ul>

    <p>El script <code>check_forensic</code>, que se encuentra en el
    directorio support de la distribución, puede ser útil para evaluar la
    salida del log forense.</p>
</summary>
<seealso><a href="../logs.html">Archivos de registro de Apache</a></seealso>
<seealso><module>mod_log_config</module></seealso>

<section id="formats"><title>Formato del log forense</title>
    <p>Cada petición se registra dos veces. La primera vez es <em>antes</em> de que se
    siga procesando (es decir, tras recibir las cabeceras). La segunda entrada de
    registro se escribe <em>después</em> del procesamiento de la petición, en el mismo
    momento en que se produce el registro normal.</p>

    <p>Para identificar cada petición, se asigna un ID de petición único.
    Este ID forense puede registrarse también en el log de transferencia normal usando la
    cadena de formato <code>%{forensic-id}n</code>. Si está usando
    <module>mod_unique_id</module>, se usará el ID que este genere.</p>

    <p>La primera línea registra el ID forense, la línea de petición y todas las cabeceras
    recibidas, separadas por el carácter de barra vertical (<code>|</code>). Una línea de
    ejemplo tiene este aspecto (todo en una sola línea):</p>

    <example>
        +yQtJf8CoAB4AAFNXBIEAAAAA|GET /manual/de/images/down.gif
        HTTP/1.1|Host:localhost%3a8080|User-Agent:Mozilla/5.0 (X11;
        U; Linux i686; en-US; rv%3a1.6) Gecko/20040216
        Firefox/0.8|Accept:image/png, <var>etc...</var>
    </example>

    <p>El carácter más al principio indica que esta es la primera línea de registro de
    esta petición. La segunda línea solo contiene un carácter menos y
    el ID de nuevo:</p>

    <example>
      -yQtJf8CoAB4AAFNXBIEAAAAA
    </example>

    <p>El script <code>check_forensic</code> recibe como argumento el nombre
    del archivo de registro. Busca esos pares de ID <code>+</code>/<code>-</code>
    y avisa si una petición no se completó.</p>
</section>

<section id="security"><title>Consideraciones de seguridad</title>
    <p>Consulte el documento <a
    href="../misc/security_tips.html#serverroot">consejos de seguridad</a>
    para más detalles sobre por qué su seguridad podría verse comprometida
    si el directorio donde se almacenan los archivos de registro puede ser escrito por
    alguien que no sea el usuario que inicia el servidor.</p>
    <p>Los archivos de registro pueden contener datos sensibles, como el contenido de las
    cabeceras <code>Authorization:</code> (que pueden contener contraseñas), por lo que
    no deberían ser legibles por nadie salvo el usuario que inicia el
    servidor.</p>
</section>

<directivesynopsis>
<name>ForensicLog</name>
<description>Establece el nombre de archivo del log forense</description>
<syntax>ForensicLog <var>filename</var>|<var>pipe</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ForensicLog</directive> se usa para
    registrar las peticiones al servidor para su análisis forense. A cada entrada de registro
    se le asigna un ID único que puede asociarse con la petición
    usando la directiva normal <directive module="mod_log_config">CustomLog</directive>.
    <module>mod_log_forensic</module> crea un token llamado
    <code>forensic-id</code>, que puede añadirse al log de transferencia
    usando la cadena de formato <code>%{forensic-id}n</code>.</p>

    <p>El argumento, que especifica la ubicación en la que
    se escribirán los registros, puede tomar uno de los dos
    tipos de valores siguientes:</p>

    <dl>
      <dt><var>filename</var></dt>
      <dd>Un nombre de archivo, relativo a <directive module="core"
      >ServerRoot</directive>.</dd>

      <dt><var>pipe</var></dt>
      <dd>El carácter de barra vertical "<code>|</code>", seguido de la ruta
      a un programa que recibirá la información de registro en su entrada
      estándar. El nombre del programa puede indicarse en relación a la directiva
      <directive module="core">ServerRoot</directive>.

      <note type="warning"><title>Seguridad:</title>
      <p>Si se usa un programa, este se ejecutará como el usuario que
      inició <program>httpd</program>. Será root si el servidor se inició
      como root; asegúrese de que el programa sea seguro o cambie a un
      usuario con menos privilegios.</p>
      </note>

      <note><title>Nota</title>
        <p>Al introducir una ruta de archivo en plataformas que no sean Unix, se debe tener
        cuidado de usar únicamente barras inclinadas, aunque la plataforma
        pueda permitir el uso de barras invertidas. En general, es una buena idea usar
        siempre barras inclinadas en todos los archivos de configuración.</p>
      </note></dd>
    </dl>
</usage>
</directivesynopsis>

</modulesynopsis>
