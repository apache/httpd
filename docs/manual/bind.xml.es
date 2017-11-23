<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1673947:1816110 (outdated) -->
<!-- Translated by: Luis Gil de Bernabé Pfeiffer -->
<!-- Reviewed by: Sergio Ramos -->

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

<manualpage metafile="bind.xml.meta">

  <title>Mapeo de Direcciones y Puertos.</title>

  <summary>
    <p>Configurando Apache HTTP Server para que escuche en una dirección y puertos específicos.</p>
  </summary>

  <seealso><a href="vhosts/">Hosts Virtuales</a></seealso>
  <seealso><a href="dns-caveats.html">Problemas de DNS</a></seealso>

  <section id="overview">
    <title>Visión General</title>

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


    <p>Cuando httpd se ejecuta, se mapea a una dirección y un puerto en la
    máquina local, y espera a recibir peticiones. Por defecto, escucha en 
    todas las direcciones de la máquina. Ahora bien, se le puede especificar 
    que escuche en un determinado puerto, o en una sola dirección IP especifica, 
    o una combinación de ambos. A menudo esto se combina con la característica
    de los <a href="vhosts/">Hosts virtuales</a>, que determina como responde el 
    <code>httpd</code> a diferentes direcciones IP, nombres de máquinas y puertos.</p>

    <p>La directiva <directive module="mpm_common">Listen</directive>
     le dice al servidor que acepte peticiones en el puerto o puertos que
     se le especifiquen al servidor, o a combinaciones de direcciones y 
     puertos. Si sólo se especifica el número del puerto en la directiva
     <directive module="mpm_common">Listen</directive>, el servidor escuchará en 
     ese puerto pero en todas las interfaces de red.
     Si además del puerto se le especifica una dirección IP, el servidor escuchará 
     en el puerto y en la interfaz de red asociado a la dirección IP 
     que se le ha especificado en la directiva. Se pueden especificar 
     múltiples directivas <directive module="mpm_common">Listen</directive> para 
     especificar un determinado número de IP´s y puertos por donde el servidor escuchará.
     El servidor por tanto, responderá a las peticiones en cualquiera de las IP´s y puertos
     listados en la directiva.</p>

    <p>Por ejemplo, para hacer que el servidor escuche en ambos puertos 80 y 8080 en todas 
    	sus interfaces de red, se usa lo siguiente:</p>

    <example>
    <highlight language="config">
Listen 80
Listen 8000
    </highlight>
    </example>

    <p>Para hacer que el servidor acepte peticiones en el puerto 80 en una sola interfaz de red, usaremos:</p>

    <example>
    <highlight language="config">
Listen 192.0.2.1:80
Listen 192.0.2.5:8000
    </highlight>
    </example>

    <p>Las direcciones IPv6 debrán ir entre '[ ]' corchetes como en el siguiente ejemplo:</p>

    <example>
    <highlight language="config">
      Listen [2001:db8::a00:20ff:fea7:ccea]:80
    </highlight>
    </example>

    <note type="warning"><p>Si se superponen directivas de tipo <directive
    module="mpm_common">Listen</directive>, dará como resultado un error fatal
    que impedirá que se inicie el servidor.</p>

    <example>
      (48)Address already in use: make_sock: could not bind to address [::]:80
    </example>

    <p>Puede mirar el <a
    href="http://wiki.apache.org/httpd/CouldNotBindToAddress">articulo de la wiki</a>
    de consejos para solucionar problemas relacionados.</p>

</note>

  </section>

  <section id="ipv6">
    <title>Consideraciones especiales con IPv6</title>

    <p>Un creciente número de plataformas implementan ya IPv6, y 
    <glossary>APR</glossary> soporta IPv6 en la mayoría de estas plataformas, 
    permitiendo así a httpd asignar sockets IPv6, y manejar las respuestas 
    enviadas a través de IPv6.</p>

    <p>Un factor bastante complejo para un administrador del httpd 
    es si un socket IPv6 puede o no manejar tanto conexiones IPv6 
    como IPv4. El manejo por httpd de conexiones IPv4 con socket IPv6 
    se debe al mapeo de direcciones IPv4 sobre IPv6, que 
    está permitido por defecto en muchas plataformas, pero no lo está 
    en sistemas FreeBSD, NetBSD y Open BSD, con el fin de que en estas 
    plataformas, cumpla con la política del sistema.
    En los sistemas que no está permitido el mapeo por defecto, 
    existe un parámetro de <program>configure</program> especial 
    para cambiar éste comportamiento para httpd.</p>

    <p>Por otro lado, en algunas plataformas, como Linux y True64, la 
    <strong>única</strong> forma para el manejo de IPv4 e IPv6 al mismo 
    tiempo es mediante direcciones mapeadas.
    Si quieres que <code>httpd</code> maneje amos tipos de conexiones IPv4 e IPv6
    con el mínimo de sockets, hay que especificar la opción 
    <code>--enable-v4-mapped</code> al <program>
    configure</program>.</p>

    <p><code>--enable-v4-mapped</code> es la opción que está estipulada por defecto
    en todos los sistemas menos en FreeBSD, NetBSD y Open BSD, por 
    lo que es probablemente como se compiló su httpd.</p>

    <p>Si lo que quiere es manejar sólo conexiones IPv4, independientemente de 
    lo que soporten <glossary>APR</glossary> y su plataforma, especifique 
    una dirección IPv4 por cada directiva 
    <directive module="mpm_common">Listen</directive>, como en el siguiente 
    ejemplo:</p>

    <example>
    <highlight language="config">
Listen 0.0.0.0:80
Listen 192.0.2.1:80
    </highlight>
    </example>

    <p>Si en cambio, su plataforma lo soporta, y lo que quiere es que su httpd 
    soporte tanto conexiones IPv4 como IPv6 en diferentes sockets (ejemplo.: para 
    deshabilitar mapeo de direcciones IPv4), especifique la opción 
    <code>--disable-v4-mapped</code> al <program>
    configure</program>. <code>--disable-v4-mapped</code> es la opción por defecto 
    en FreeBSD, NetBSD y OpenBSD.</p>
  </section>

  <section id="protocol">
    <title>Especificar el Protocolo en el Listen</title>
    <p>El segundo argumento en la directiva <directive module="mpm_common">Listen</directive>
    el <var>protocolo</var> que es opcional no es algo que se requiera en las configuraciones.
    Si éste argumento no se especifica, <code>https</code> es el protocolo 
    usado por defecto en el puerto 443 y <code>http</code>  para el resto.
    El protocolo se utiliza para determinar que módulo deberá manejar la petición,
    y se le aplicarán optimizaciones específicas del protocolo con la directiva
    <directive module="core">AcceptFilter</directive>.</p>

    <p>Sólo necesitará especificar el protocolo si no está escuchando en un puerto
    de los que son estándares, por ejemplo si ejecuta un sitio web <code>https</code> en el puerto 8443:</p>

    <example>
    <highlight language="config">
      Listen 192.170.2.1:8443 https
    </highlight>
    </example>
  </section>

  <section id="virtualhost">
    <title>Como Funciona en los Hosts Virtuales</title>

    <p> La directiva <directive
    module="mpm_common">Listen</directive> no implementa los
    Hosts Virtuales - solo le dice al servidor en que direcciones 
    y puertos debe escuchar. Si no hay directiva 
    <directive module="core" type="section">VirtualHost</directive>
    en uso, el servidor se comportará de la misma manera para todas las 
    peticiones aceptadas. Ahora bien,
    <directive module="core" type="section">VirtualHost</directive>
    puede ser usado para especificar un comportamiento diferente en una o 
    varias direcciones o puertos.
    Para implementar los Hosts Virtuales, antes se le tiene que decir al servidor
    que direcciones y puertos van a ser usados. 
    Después de esto, se deberá especificar una sección de la directiva
    <directive module="core" type="section">VirtualHost</directive> 
    especificando direcciones y puertos que se van a usar en el Host Virtual
    Note que si se configura un 
    <directive module="core" type="section">VirtualHost</directive>
    para una dirección y puerto en el que el servidor no está escuchando,
    no se podrá acceder al Host Virtual.</p>
  </section>
</manualpage>
