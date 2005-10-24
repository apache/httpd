<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 328032 -->

<!--
 Copyright 2005 The Apache Software Foundation or its licensors,
                as applicable

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

<manualpage metafile="bind.xml.meta">

  <title>Direcciones IP y puertos de escucha</title>

  <summary>
    <p>C&#243;mo configurar Apache para que escuche en direcciones IP
    y puertos espec&#237;ficos.</p>
  </summary>

  <seealso><a href="vhosts/">Hosts virtuales</a></seealso>
  <seealso><a href="dns-caveats.html">Asuntos relacionados con DNS</a></seealso>

  <section id="overview">
    <title>Introducci&#243;n</title>

    <related>
      <modulelist>
        <module>core</module>
        <module>mpm_common</module>
      </modulelist>
      <directivelist>
        <directive module="core" type="section">VirtualHost</directive>
        <directive module="mpm_common">Listen</directive>
      </directivelist>
    </related>


    <p>Cuando Apache se inicia, comienza a esperar peticiones
    entrantes en determinados puertos y direcciones de la m&#225;quina
    en la que se est&#225; ejecutando. Sin embargo, si quiere que
    Apache escuche solamente en determinados puertos espec&#237;ficos,
    o solamente en determinadas direcciones, o en una combinaci&#243;n
    de ambos, debe especificarlo adecuadamente. Esto puede adem&#225;s
    combinarlo con la posibilidad de usar hosts virtuales,
    funcionalidad con la que un servidor Apache puede responder a
    peticiones en diferentes direcciones IP, diferentes nombres de
    hosts y diferentes puertos.</p>

    <p>La directiva <directive module="mpm_common">Listen</directive>
    le indica al servidor que acepte peticiones entrantes solamente en
    los puertos y en las combinaciones de puertos y direcciones que se
    especifiquen. Si solo se especifica un n&#250;mero de puerto en la
    directiva <directive module="mpm_common">Listen</directive> el
    servidor escuchar&#225; en ese puerto, en todas las interfaces de
    red de la m&#225;quina. Si se especifica una direcci&#243;n IP y
    un puerto, el servidor escuchar&#225; solamente en la interfaz de
    red a la que pertenezca esa direcci&#243;n IP y solamente en el
    puerto indicado. Se pueden usar varias directivas <directive
    module="mpm_common">Listen</directive> para
    especificar varias direcciones IP y puertos de escucha. El
    servidor responder&#225; a las peticiones de todas las direcciones
    y puertos que se incluyan.</p>

    <p>Por ejemplo, para hacer que el servidor acepte conexiones tanto
    en el puerto 80 como en el puerto 8000, puede usar:</p>

    <example>
      Listen 80<br />
      Listen 8000
    </example>

    <p>Para hacer que el servidor acepte conexiones en dos interfaces
    de red y puertos espec&#237;ficos, use</p>

    <example>
      Listen 192.170.2.1:80<br />
      Listen 192.170.2.5:8000
    </example>

    <p>Las direcciones IPv6 deben escribirse entre corchetes, como en el siguiente ejemplo:</p>

    <example>
      Listen [2001:db8::a00:20ff:fea7:ccea]:80
    </example>
  </section>

  <section id="ipv6">
    <title>Consideraciones especiales para IPv6</title>

    <p>Cada vez m&#225;s plataformas implementan IPv6, y APR soporta
    IPv6 en la mayor parte de esas plataformas, permitiendo que Apache
    use sockets IPv6 y pueda tratar las peticiones que se env&#237;an
    con IPv6.</p>

    <p>Un factor de complejidad para los administradores de Apache es
    si un socket IPv6 puede tratar tanto conexiones IPv4 como
    IPv6. Para tratar conexiones IPv4 con sockets IPv6 se utiliza un
    traductor de direcciones IPv4-IPv6, cuyo uso est&#225; permitido
    por defecto en la mayor parte de las plataformas, pero que
    est&#225; desactivado por defecto en FreeBSD, NetBSD, y OpenBSD
    para cumplir con la pol&#237;tica system-wide en esas
    palaformas. Pero incluso en los sistemas en los que no est&#225;
    permitido su uso por defecto, un par&#225;metro especial de
    <program>configure</program> puede modificar ese
    comportamiento.</p>

    <p>Si quiere que Apache trate conexiones IPv4 y IPv6 con un
    m&#237;nimo de sockets, lo que requiere traducir direcciones IPv4
    a IPv6, especifique la opci&#243;n de <program>configure</program>
    <code>--enable-v4-mapped</code> y use directivas <directive
    module="mpm_common">Listen</directive> gen&#233;ricas de la
    siguiente forma:</p>

    <example>
      Listen 80
    </example>

    <p>Con <code>--enable-v4-mapped</code>, las directivas Listen en
    el fichero de configuraci&#243;n por defecto creado por Apache
    usar&#225;n ese formato. <code>--enable-v4-mapped</code> es el
    valor por defecto en todas las plataformas excepto en FreeBSD,
    NetBSD, y OpenBSD, de modo que esa es probablemente la manera en
    que su servidor Apache fue construido.</p>

    <p>Si quiere que Apache solo procese conexiones IPv4, sin tener en
    cuenta cu&#225;l es su plataforma o qu&#233; soporta APR, especifique
    una direcci&#243;n IPv4 en todas las directivas <directive
    module="mpm_common">Listen</directive>, como en
    estos ejemplos:</p>

    <example>
      Listen 0.0.0.0:80<br />
      Listen 192.170.2.1:80
    </example>

    <p>Si quiere que Apache procese conexiones IPv4 y IPv6 en sockets
    diferentes (es decir, deshabilitar la conversi&#243;n de
    direcciones IPv4 a IPv6), especifique la opci&#243;n de
    <program>configure</program> <code>--disable-v4-mapped</code> y
    use directivas Listen espec&#237;ficas como en el siguiente ejemplo:</p>

    <example>
      Listen [::]:80<br />
      Listen 0.0.0.0:80
    </example>

    <p>Con <code>--disable-v4-mapped</code>, las directivas Listen en
    el fichero de configuraci&#243;n que Apache crea por defecto
    usar&#225;n ese formato. <code>--disable-v4-mapped</code> se usa
    por defecto en FreeBSD, NetBSD, y OpenBSD.</p>

  </section>

  <section id="virtualhost">
    <title>C&#243;mo funciona este mecanismo en hosts virtuales</title>

    <p><directive module="mpm_common">Listen</directive> no implementa
    hosts virtuales. Solo le dice al servidor
    principal en qu&#233; direcciones y puertos tiene que escuchar. Si no
    se usan directivas <directive module="core"
    type="section">VirtualHost</directive>, el servidor se comporta de
    la misma manera con todas las peticiones que se acepten. Sin
    embargo, <directive module="core"
    type="section">VirtualHost</directive> puede usarse para
    especificar un comportamiento diferente en una o varias
    direcciones y puertos. Para implementar un host virtual, hay que
    indicarle primero al servidor que escuche en aquellas direcciones y
    puertos a usar. Entonces se debe crear un una secci&#243;n
    <directive module="core" type="section">VirtualHost</directive>
    en una direcci&#243;n y puerto espec&#237;ficos para determinar
    el comportamiento de ese host virtual. Tenga en cuenta que si se
    especifica en una secci&#243;n <directive module="core"
    type="section">VirtualHost</directive> una direcci&#243;n y puerto
    en los que el servidor no est&#225; escuchando, ese host virtual no
    podr&#225; ser accedido.</p>
  </section>
</manualpage>
