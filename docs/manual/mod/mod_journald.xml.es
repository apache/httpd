<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1675797 -->
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

<modulesynopsis metafile="mod_journald.xml.meta">

<name>mod_journald</name>
<description>Proporciona el proveedor de ErrorLog "journald"</description>
<status>Extension</status>
<sourcefile>mod_journald.c</sourcefile>
<identifier>journald_module</identifier>

<summary>
    <p>Este módulo proporciona el proveedor de ErrorLog "journald". Permite
    registrar mensajes de error y CustomLog/TransferLog mediante systemd-journald(8).</p>
</summary>

<section id="structured">
    <title>Registro estructurado</title>
    <p>Systemd-journald permite el registro estructurado y, por tanto, es
    posible filtrar los mensajes registrados según distintas variables.
    Las variables admitidas actualmente son:
    </p>
    <dl>
      <dt><code>LOG</code></dt>
      <dd>El nombre del registro. Para ErrorLog, el valor es "error_log".
          Para CustomLog o TransferLog, el valor es el primer argumento de
          estas directivas.</dd>
      <dt><code>REQUEST_HOSTNAME</code></dt>
      <dd>El host, tal y como se establece mediante la URI completa o la cabecera
          Host: de la petición.</dd>
      <dt><code>REQUEST_USER</code></dt>
      <dd>Si se realizó una comprobación de autenticación, se establece con el nombre
          de usuario.</dd>
      <dt><code>REQUEST_USERAGENT_IP</code></dt>
      <dd>La dirección que originó la petición.</dd>
      <dt><code>REQUEST_URI</code></dt>
      <dd>La parte de ruta de la URI, o "/" si no se proporciona ninguna ruta.</dd>
      <dt><code>SERVER_HOSTNAME</code></dt>
      <dd>El nombre de host del servidor para el que se ha generado el
          mensaje de registro.</dd>
    </dl>

    <p>Estas variables pueden usarse, por ejemplo, para mostrar solo los mensajes de registro
    de una URI concreta mediante <code>journalctl</code>:
    </p>

    <highlight>journalctl REQUEST_URI=/index.html -a</highlight>

    <p>Para más ejemplos, consulte la documentación de systemd-journalctl.</p>
</section>

<section id="examples">
    <title>Ejemplos</title>

    <p>Usar <code>journald</code> en la directiva ErrorLog (vea <module>core</module>)
    en lugar de un nombre de archivo activa el registro mediante systemd-journald(8)
    si el sistema lo admite.
    </p>

    <highlight language="config">
ErrorLog journald
    </highlight>

    <p>Usar <code>journald</code> como proveedor de registro de errores en la directiva
    CustomLog (vea <module>mod_log_config</module>) activa
    el registro mediante systemd-journald(8) si el sistema lo admite.
    </p>

    <highlight language="config">
CustomLog "journald" "%h %l %u %t \"%r\" %>s %b"
    </highlight>

    <note type="warning"><title>Advertencia de rendimiento</title><p>
    Actualmente, systemd-journald no está diseñado para un registro de alto rendimiento
    y registrar access_log en systemd-journald podría reducir considerablemente
    el rendimiento.
    </p></note>

</section>

</modulesynopsis>
