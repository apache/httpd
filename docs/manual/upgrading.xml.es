<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.en.xsl"?>
<!-- English Revision: 103430 (outdated: 106090) -->

<!--
 Copyright 2004 The Apache Software Foundation

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

<manualpage metafile="upgrading.xml.meta">

<title>Migrar su instalaci&#243;n de la versi&#243;n 1.3 a la
2.0</title>

<summary>
  <p>Este documento recoge infomaci&#243;n cr&#237;tica sobre el
  proceso de actulizaci&#243;n de la versi&#243;n de Apache que
  usa. Se trata de peque&#241;os comentarios. Puede encontrar m&#225;s
  informaci&#243;n tanto en <a href="new_features_2_0.html">Nuevas
  funcionalidades</a>, como en el archivo
  <code>src/CHANGES</code>.</p>
</summary>
<seealso><a href="new_features_2_0.html">Visi&#243;n general de las
nuevas funcionalidades de Apache 2.0</a></seealso>

  <section id="compile-time">
    <title>Cambios en el proceso de configuraci&#243;n y
    compilaci&#243;n</title>

    <ul>
      <li>Apache usa ahora <code>autoconf</code> y
      <code>libtool</code> <a href="install.html"> en el proceso de
      compilaci&#243;n</a>.  Este sistema es parecido aunque no igual
      al sistema APACI de Apache 1.3.</li>

      <li>Adem&#225;s de la selecci&#243;n de m&#243;dulos habitual
      que puede hacer al compilar, en Apache 2.0 la mayor parte del
      procesamiento de las petici&#243;n es llevada a cabo por los <a
      href="mpm.html">M&#243;dulos de MultiProcesamiento</a>
      (MPMs).</li>
    </ul>
  </section>

  <section id="run-time">
    <title>Cambios en el proceso de la configuraci&#243;n inicial del
    servidor</title>

    <ul>
      <li>Muchas directivas que no pertenic&#237;an al conjunto
      b&#225;sico en Apache 1.3 est&#225;n ahora en los MPMs. Si desea
      que el nuevo servidor de comporte de la forma m&#225;s parecida
      posible a Apache 1.3, debe seleccionar el M&#243;dulo de
      MultiProcesamiento <module>prefork</module>. Otros MPMs tienen
      diferentes directivas para controlar el proceso de creaci&#243;n
      y procesamiento de peticiones.</li>

      <li>El <a href="mod/mod_proxy.html">m&#243;dulo proxy</a> ha
      sido remodelado para ponerlo al d&#237;a con la
      especificaci&#243;n HTTP/1.1.  Entre los cambios m&#225;s
      importantes est&#225; el que ahora el control de acceso al proxy
      est&#225; dentro de un bloque <directive type="section"
      module="mod_proxy">Proxy</directive> en lugar de en un bloque
      <code>&lt;Directory proxy:&gt;</code>.</li>

      <li>El procesamiento de<code>PATH_INFO</code> (la informacion de
      path que aparece tras un nombre de fichero v&#225;lido) ha
      cambiado para algunos m&#243;dulos. M&#243;dulos que fueron
      previamente implementados como un handle pero ahora son
      implementados como filtros puede que no acepten ahora peticiones
      que incluyan <code>PATH_INFO</code>. Filtros como <a
      href="mod/mod_include.html">INCLUDES</a> o <a
      href="http://www.php.net/">PHP</a> est&#225;n implementados
      encima del handler principal (core handler) core handler, y por
      tanto rechazan peticiones con <code>PATH_INFO</code>. Puede usar
      la directiva <directive module="core">AcceptPathInfo</directive>
      para forzar al handler principal a aceptar peticiones con
      <code>PATH_INFO</code> y por tanto restaurar la habilidad de
      usar <code>PATH_INFO</code> en server-side includes.</li>

      <li>La directiva <directive
      module="mod_negotiation">CacheNegotiatedDocs</directive> toma
      ahora como argumento <code>on</code> u <code>off</code>. Las
      instacias existentes de <directive
      >CacheNegotiatedDocs</directive> deben reemplazarse por
      <code>CacheNegotiatedDocs on</code>.</li>

      <li>
        La directiva <directive
        module="core">ErrorDocument</directive> no usa ya dobles
        comillas al principio del argumento para indicar el mensaje de
        texto que tiene que mostrarse. En lugar de esto, se debe poner
        entre comillas todo el mensaje. Por ejemplo,

        <example>
          ErrorDocument 403 "Mensaje
        </example>
        debe sustituirse por

        <example>
          ErrorDocument 403 "Mensaje"
        </example>

        Si el segundo argumento no es una URL o una ruta v&#225;lida a
        un archivo, ser&#225; tratado como un mensaje de texto.
      </li>

      <li>Las directivas <code>AccessConfig</code> y
      <code>ResourceConfig</code> han desaparecido.  Las instancias
      existentes de estas directivas pueden sustituirse por la
      directiva <directive module="core">Include</directive> que tiene
      una funcionalidad equivalente. Si hac&#237;a uso de los valores
      por defecto de esas directivas sin incluirlas en los ficheros de
      configuraci&#243;n, puede que necesite a&#241;adir <code>Include
      conf/access.conf</code> e <code>Include conf/srm.conf</code> a
      su fichero <code>httpd.conf</code>. Para asegurarse de que
      Apache lee el fichero de configuraci&#243;n en el mismo orden
      que asum&#237;an las antiguas directivas, las directivas
      <directive module="core">Include</directive> deben ser
      reemplazadas al final del fichero <code>httpd.conf</code>, con
      la de <code>srm.conf</code> precediendo a la de
      <code>access.conf</code>.</li>

      <li>Las directivas <code>BindAddress</code> y <code>Port</code>
      no existen ya. Las funcionalidades que ofrec&#237;an esas
      directivas est&#225;n ahora cubiertas por la directiva
      <directive module="mpm_common">Listen</directive>, que es mucho
      m&#225;s flexible.</li>

      <li>Otro uso de la directiva <code>Port</code> en Apache 1.3 era
      fijar el n&#250;mero de puerto que se usaba para URLs
      autoreferenciadas. La directiva equivalente en Apache 2.0 es la
      nueva directiva <directive module="core">ServerName</directive>:
      este cambio se ha introducido para permitir la
      especificaci&#243;n del nombre de host <em>y</em> del
      n&#250;mero de puerto para URLs autorreferenciadas en una sola
      directiva.</li>

      <li>La directiva <code>ServerType</code> ha dejado de existir.
      El m&#233;todo usado para servir peticiones est&#225; ahora
      determinado por la selecci&#243;n del M&#243;dulo de
      MultiProcesamiento. Actualmente no hay dise&#241;ado un MPM que
      pueda ser ejecutado por inetd.</li>

      <li>Los m&#243;dulos <code>mod_log_agent</code> y
      <code>mod_log_referer</code> que conten&#237;an las directivas
      <code>AgentLog</code>, <code>RefererLog</code> y
      <code>RefererIgnore</code> han desaparecido. Los logs de agente
      y de referer est&#225;n disponibles todav&#237;a usando la
      directiva <directive
      module="mod_log_config">CustomLog</directive> del m&#243;dulo
      <module>mod_log_config</module>.</li>

      <li>las directivas <code>AddModule</code> y
      <code>ClearModuleList</code> no est&#225;n presentes en la nueva
      versi&#243;n.  Estan directivas se usaban para asegurarse de que
      los m&#243;dulos pudieran activarse en el orden correcto. La
      nueva API de Apache 2.0 permite a los m&#243;dulos especificar
      expl&#237;citamente su orden de activaci&#243;n, eliminando la
      necesidad de estas directivas.</li>

      <li>La directiva <code>FancyIndexing</code> se ha eliminado.  La
      funcionalidad que cubr&#237;a est&#225; ahora disponible a
      trav&#233;s de la opci&#243;n <code>FancyIndexing</code> de la
      directiva <directive
      module="mod_autoindex">IndexOptions</directive>.</li>

      <li>La t&#233;cnica de negociaci&#243;n de contenido MultiViews
      ofrecida por <module>mod_negotiation</module> es ahora m&#225;s
      estricta en su algoritmo de selecci&#243;n de ficheros y solo
      seleccionar&#225; ficheros <em>negociables</em>.  El antiguo
      comportamiento puede restaurarse usando la directiva <directive
      module="mod_mime">MultiviewsMatch</directive>.</li>

    </ul>
  </section>

  <section id="misc">
    <title>Cambios de menor importancia</title>

    <ul>
      <li>El m&#243;dulo <module>mod_auth_digest</module>, que era
      experimental en Apache 1.3, es ahora un m&#243;dulo
      est&#225;ndar.</li>

      <li>El m&#243;dulo <code>mod_mmap_static</code>, que era
      experimental en Apache 1.3, ha sido sustituido por el
      m&#243;dulo <module>mod_file_cache</module>.</li>

      <li>La distribuci&#243;n de Apache ha sido reorganizada por
      completo para que no contenga a partir de ahora el directorio
      independiente <code>src</code>. En su lugar, el c&#243;digo
      fuente se ha organizado a partir del directorio principal de la
      distribuci&#243;n, y las intalaciones del servidor compilado
      deben hecerse en un directorio diferente.</li>
    </ul>
  </section>

  <section id="third-party">
    <title>M&#243;dulos de terceras partes</title>

    <p>La API de Apache 2.0 ha sufrido grandes cambios respecto a la
    versi&#243;n 1.3. Los m&#243;dulos que se dise&#241;aron para la
    API de Apache 1.3 <strong>no</strong> funcionar&#225;n si no se
    hacen las modificaciones necasarias para adaptarlos a Apache 2.0.
    En la <a href="developer/">documentaci&#243;n para
    desarrolladores</a> puede encontrar informaci&#243;n detallada
    sobre este asunto.</p>
  </section>
</manualpage>




