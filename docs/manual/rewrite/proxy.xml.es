<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933067:1933622 (outdated) -->

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

<manualpage metafile="proxy.xml.meta">
  <parentdocument href="./">Rewrite</parentdocument>

<title>Uso de mod_rewrite para Proxy</title>

<summary>

<p>Este documento complementa la <module>mod_rewrite</module>
<a href="../mod/mod_rewrite.html">documentación de referencia</a>. Describe
cómo usar la bandera [P] de RewriteRule para hacer proxy de contenido a otro servidor.
Se proporcionan varias recetas que describen escenarios comunes.</p>

</summary>
<seealso><a href="../mod/mod_rewrite.html">Documentación del módulo</a></seealso>
<seealso><a href="intro.html">Introducción a mod_rewrite</a></seealso>
<seealso><a href="remapping.html">Redirección y remapeo</a></seealso>
<seealso><a href="access.html">Control de acceso</a></seealso>
<seealso><a href="vhosts.html">Hosts virtuales</a></seealso>
<!--<seealso><a href="proxy.html">Proxy</a></seealso>-->
<seealso><a href="rewritemap.html">Uso de RewriteMap</a></seealso>
<seealso><a href="advanced.html">Técnicas avanzadas</a></seealso>
<seealso><a href="avoid.html">Cuándo no usar mod_rewrite</a></seealso>

<section id="dynamic-proxy">

  <title>Hacer proxy de contenido con mod_rewrite</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
    <p>
    <module>mod_rewrite</module> proporciona la bandera [P], que permite pasar URLs,
    a través de <module>mod_proxy</module>, a otro servidor. Aquí se dan dos ejemplos. En
    un ejemplo, una URL se pasa directamente a otro servidor, y se sirve
    como si fuera una URL local. En el otro ejemplo, hacemos proxy del
    contenido faltante a un servidor backend.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>
      <p>Para simplemente mapear una URL a otro servidor, usamos la bandera [P], de la
      siguiente manera:</p>

<highlight language="config">
RewriteEngine  on
RewriteBase    "/products/"
RewriteRule    "^widget/(.*)$"  "http://product.example.com/widget/$1"  [P]
ProxyPassReverse "/products/widget/" "http://product.example.com/widget/"
</highlight>

   <p>En el segundo ejemplo, hacemos proxy de la solicitud solo si no podemos encontrar
   el recurso localmente. Esto puede ser muy útil cuando está migrando
   de un servidor a otro, y no está seguro de si todo el contenido
   ha sido migrado todavía.</p>

<highlight language="config">
RewriteCond "%{REQUEST_FILENAME}"       !-f
RewriteCond "%{REQUEST_FILENAME}"       !-d
RewriteRule "^/(.*)"                    "http://old.example.com/$1" [P]
ProxyPassReverse "/" "http://old.example.com/"
</highlight>
    </dd>

    <dt>Discusión:</dt>

    <dd><p>En cada caso, añadimos una directiva <directive
    module="mod_proxy">ProxyPassReverse</directive> para asegurar
    que cualquier redirección emitida por el backend se pase correctamente al
    cliente.</p>

    <p>Considere usar <directive
    module="mod_proxy">ProxyPass</directive> o <directive
    module="mod_proxy">ProxyPassMatch</directive> siempre que sea posible en
    preferencia a <module>mod_rewrite</module>.</p>
    </dd>
  </dl>

</section>

</manualpage>
