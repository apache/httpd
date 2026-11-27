<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1883046 -->
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

<modulesynopsis metafile="mod_proxy_uwsgi.xml.meta">

<name>mod_proxy_uwsgi</name>
<description>Módulo de pasarela UWSGI para <module>mod_proxy</module></description>
<status>Extension</status>
<sourcefile>mod_proxy_uwsgi.c</sourcefile>
<identifier>proxy_uwsgi_module</identifier>
<compatibility>Disponible en la versión 2.4.30 y posteriores</compatibility>

<summary>
    <p>Este módulo <em>requiere</em> el servicio de <module
    >mod_proxy</module>. Proporciona soporte para el
    <a href="http://uwsgi-docs.readthedocs.io/en/latest/index.html">protocolo UWSGI</a>.</p>

    <p>Por lo tanto, para poder manejar el protocolo UWSGI,
    <module>mod_proxy</module> y <module>mod_proxy_uwsgi</module> deben
    estar presentes en el servidor.</p>

    <note type="warning"><title>Advertencia</title>
      <p>No active el proxy hasta que haya <a
      href="mod_proxy.html#access">asegurado su servidor</a>. Los servidores
      proxy abiertos son peligrosos tanto para su red como para Internet
      en general.</p>
    </note>
</summary>

<seealso><module>mod_proxy</module></seealso>
<seealso><module>mod_proxy_balancer</module></seealso>

<section id="examples"><title>Ejemplos</title>
    <p>Recuerde que, para que los siguientes ejemplos funcionen, debe
    activar <module>mod_proxy</module> y <module>mod_proxy_uwsgi</module>.</p>

    <example><title>Pasarela sencilla</title>
    <highlight language="config">
ProxyPass "/uwsgi-bin/" "uwsgi://localhost:4000/"
      </highlight>
    </example>

    <p>La pasarela balanceada necesita <module>mod_proxy_balancer</module> y
    al menos un módulo de algoritmo de balanceo de carga, como
    <module>mod_lbmethod_byrequests</module>, además de los módulos de
    proxy mencionados anteriormente. <module>mod_lbmethod_byrequests</module> es el
    valor por defecto, y se usará en este ejemplo de configuración.</p>

    <example><title>Pasarela balanceada</title>
    <highlight language="config">
ProxyPass "/uwsgi-bin/" "balancer://somecluster/"
&lt;Proxy balancer://somecluster&gt;
    BalancerMember uwsgi://localhost:4000
    BalancerMember uwsgi://localhost:4001
&lt;/Proxy&gt;
    </highlight>
    </example>
</section>

</modulesynopsis>
