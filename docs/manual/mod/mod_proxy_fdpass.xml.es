<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1717063 -->
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

<modulesynopsis metafile="mod_proxy_fdpass.xml.meta">

<name>mod_proxy_fdpass</name>
<description>Módulo de soporte de proceso externo fdpass para
<module>mod_proxy</module></description>
<status>Extension</status>
<sourcefile>mod_proxy_fdpass.c</sourcefile>
<identifier>proxy_fdpass_module</identifier>
<compatibility>Disponible en Unix en la versión 2.3 y posteriores</compatibility>

<summary>
    <p>Este módulo <em>requiere</em> el servicio de <module
    >mod_proxy</module>. Proporciona soporte para pasar el socket del
    cliente a otro proceso.</p>

    <p><code>mod_proxy_fdpass</code> usa la capacidad de los sockets de dominio
    AF_UNIX para <a href="http://www.freebsd.org/cgi/man.cgi?query=recv">pasar un
    descriptor de archivo abierto</a> y permitir que otro proceso termine de atender una petición.
    </p>

    <p>El módulo dispone de una interfaz de proveedor <code>proxy_fdpass_flusher</code>,
    que permite que otro módulo envíe opcionalmente las cabeceras de respuesta, o incluso
    el comienzo del cuerpo de la respuesta. El proveedor <code>flush</code> por defecto
    desactiva el keep-alive y envía las cabeceras de respuesta, dejando que el proceso
    externo solo tenga que enviar el cuerpo de la respuesta.
    </p>

    <p>Para usar otro proveedor, debe establecer el parámetro <code>flusher</code>
    en la directiva <directive module="mod_proxy">ProxyPass</directive>.
    </p>

    <p>Por ahora, el único dato que se pasa al proceso externo es el socket del
    cliente. Para recibir un socket de cliente, llame a recvfrom con un
    <a href="http://www.kernel.org/doc/man-pages/online/pages/man3/cmsg.3.html"
    ><code>struct cmsghdr</code></a> asignado. Versiones futuras de este módulo podrían incluir
    más datos tras el socket del cliente, pero esto no está implementado por ahora.
    </p>
</summary>

<seealso><module>mod_proxy</module></seealso>
</modulesynopsis>
