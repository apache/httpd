<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.en.xsl"?>
<!-- English Revision: 106849 -->

<!--
 Copyright 2004-2005 The Apache Software Foundation or it licensors,
                     as applicable.


 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<manualpage metafile="index.xml.meta">
<parentdocument href="../"/>

   <title>Documentaci&#243;n sobre Hosting Virtual en Apache</title>

<summary>

    <p>El t&#233;rmino <cite>Hosting Virtual</cite> se refiere a hacer
    funcionar m&#225;s de un sitio web (tales como
    <code>www.company1.com</code> y <code>www.company2.com</code>) en
    una sola m&#225;quina. Los sitios web virtuales pueden estar "<a
    href="ip-based.html">basados en direcciones IP</a>", lo que
    significa que cada sitio web tiene una direcci&#243;n IP diferente, o
    "<a href="name-based.html">basados en nombres diferentes</a>", lo
    que significa que con una sola direcci&#243;n IP est&#225;n funcionando
    sitios web con diferentes nombres (de dominio). El hecho de que est&#233;n
    funcionando en la misma m&#225;quina f&#237;sica pasa completamente
    desapercibido para el usuario que visita esos sitios web.</p>

    <p>Apache fue uno de los primeros servidores web en soportar
    hosting virtual basado en direcciones IP. Las versiones 1.1 y
    posteriores de Apache soportan hosting virtual (vhost) basado tanto
    en direcciones IP como basado en nombres. &#201;sta &#250;ltima variante de
    hosting virtual se llama algunas veces <em>basada en host</em> o
    <em>hosting virtual no basado en IP</em>.</p>

    <p>M&#225;s abajo se muestra un listado de documentos que explican en
    detalle c&#243;mo funciona el hosting virtual en las versiones de
    Apache 1.3 y posteriores.</p>

</summary>

<seealso><module>mod_vhost_alias</module></seealso>
<seealso><a href="name-based.html">Hosting virtual basado en nombres</a></seealso>
<seealso><a href="ip-based.html">Hosting virtual basado en IPs</a></seealso>
<seealso><a href="examples.html">Ejemplo de Hosting Virtual</a></seealso>
<seealso><a href="fd-limits.html">L&#237;mites de descriptores de ficheros</a></seealso>
<seealso><a href="mass.html">Hosting virtual masivo</a></seealso>
<seealso><a href="details.html">Detalles del proceso de selecci&#243;n de
host virtual</a></seealso>

<section id="support"><title>Soporte de Hosting Virtual</title>

    <ul>
      <li><a href="name-based.html">Hosting virtual basado en
      nombres</a> (M&#225;s de un sitio web con una sola direcci&#243;n IP)</li>
      <li><a href="ip-based.html">Hosting virtual basado en IPs</a>
      (Una direcci&#243;n IP para cada sitio web)</li>
      <li><a href="examples.html">Ejemplos t&#237;picos de
      configuraci&#243;n para usar hosting virtual</a></li>
      <li><a href="fd-limits.html">L#237;mites a los descriptores de
      ficheros</a> (o, <em>demasiados ficheros de registro</em>)</li>
      <li><a href="mass.html">Configuraci&#243;n din&#225;mica de
      Hosting virtual masivo</a></li>
      <li><a href="details.html">Discusi&#243;n en profundidad sobre el
      proceso de selecci&#243;n de hosting virtual</a></li>
    </ul>

</section>

<section id="directives"><title>Directivas de configuraci&#243;n</title>

    <ul>
      <li><directive type="section"
           module="core">VirtualHost</directive></li>
      <li><directive module="core">NameVirtualHost</directive></li>
      <li><directive module="core">ServerName</directive></li>
      <li><directive module="core">ServerAlias</directive></li>
      <li><directive module="core">ServerPath</directive></li>
    </ul>

    <p>Si est&#225; tratando de solucionar problemas de
    configuraci&#243;n de su hosting virtual, puede que le sea de
    utilidad usar la opci&#243;n de l&#237;nea de comandos de Apache
    <code>-S</code>. Es decir, el siguiente comando:</p>

    <example>
    /usr/local/apache2/bin/httpd -S
    </example>

    <p>Este comando le devolver&#225; una descripci&#243;n de
    c&#243;mo Apache analiza e interpreta el fichero de
    configuraci&#243;n. Para saber si contiene errores de
    configuraci&#243;n, es conveniente que examine con atenci&#243;n
    las direcciones IP y los nombres de servidor que est&#225;
    usando. (Consulte la documentaci&#243;n sobre el programa
    <program>httpd</program> para obtener informaci&#243;n sobre otras
    opciones de l&#237;nea de comandos)</p>

</section>
</manualpage>



