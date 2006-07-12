<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 421174 -->

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

<manualpage metafile="dns-caveats.xml.meta">

  <title>Asuntos relacionados con Apache y las DNS</title>

  <summary>
    <p>Este documento puede resumirse en la siguiente frase: no
    configure Apache de manera que el an&#225;lisis sint&#225;ctico de
    los ficheros de configuraci&#243;n tenga que confiar en
    resoluciones DNS. Si Apache necesita de resoluciones DNS para
    analizar los ficheros de configuraci&#243;n, entonces su servidor
    puede no funcionar correctamente (por ejemplo, podr&#237;a no
    iniciarse), o sufrir ataques de denegaci&#243;n o robo de servicio
    (incluyendo que otas web puedan "robar" peticiones de otras
    web).</p>
  </summary>

  <section id="example">
    <title>Un ejemplo sencillo</title>

    <example>
      &lt;VirtualHost www.abc.dom&gt; <br />
      ServerAdmin webgirl@abc.dom <br />
      DocumentRoot /www/abc <br />
      &lt;/VirtualHost&gt;
    </example>

    <p>Para que Apache funcione correctamente, es imprescindible
    conocer dos aspectos sobre cada host virtual: el valor de la
    directiva <directive module="core">ServerName</directive> y al
    menos una direcci&#243;n IP en la que servidor escuchar&#225; y
    responder&#225; a las peticiones que se produzcan. El ejemplo
    mostrado arriba no incluye la direccion IP, de manera que Apache
    tiene que usar una resoluci&#243;n DNS para encontrar la
    direcci&#243;n IP correspondiente a <code>www.abc.dom</code>. Si
    por alguna raz&#243;n la resoluci&#243;n DNS no est&#225;
    disponible en el momento en que su servidor est&#225; analizando
    sint&#225;nticamente su fichero de configuraci&#243;n, entonces
    este host virtual <strong>no se configurar&#225;</strong> y no
    ser&#225; capaz de responder a ninguna de las peticiones que se
    hagan a ese host virtual (en las versiones de Apache anteriores a
    la 1.2 el servidor ni siquiera se iniciaba).</p>

    <p>Suponga que <code>www.abc.dom</code> tiene como direcci&#243;n
    IP la 10.0.0.1. Considere la siguiente configuraci&#243;n:</p>

    <example>
      &lt;VirtualHost 10.0.0.1&gt; <br />
      ServerAdmin webgirl@abc.dom <br />
      DocumentRoot /www/abc <br />
      &lt;/VirtualHost&gt;
    </example>

    <p>Ahora Apache necesita hacer una b&#250;squeda DNS inversa para
    encontrar el <code>ServerName</code> de este host virtual. Si esta
    b&#250;squeda inversa falla entonces el host virtual se
    desactivar&#225; parcialmente (en las versiones de Apache
    anteriores a la 1.2 el servidor ni siquiera se iniciaba). Si el
    host virtual est&#225; basado en el nombre, entonces se
    desactivar&#225; completamente, pero si est&#225; basado en la
    direcci&#243;n IP, entonces funcionar&#225; para la mayor parte de
    las cosas. Sin embargo, si Apache tiene que generar en alg&#250;n
    momento una URL completa que incluya el nombre del servidor, no
    ser&#225; capaz de generar una URL v&#225;lida.</p>

    <p>Aqu&#237; tiene una forma de evitar ambos problemas:</p>

    <example>
      &lt;VirtualHost 10.0.0.1&gt; <br />
      ServerName www.abc.dom <br />
      ServerAdmin webgirl@abc.dom <br />
      DocumentRoot /www/abc <br />
      &lt;/VirtualHost&gt;
    </example>
  </section>

  <section id="denial">
    <title>Denegaci&#243;n de servicio</title>

    <p>Hay (al menos) dos formas de que ocurra una denegaci&#243;n de
    servicio. Si est&#225; ejecutando una versi&#243;n de Apache
    anterior a la 1.2, entonces su servidor no se iniciar&#225; si una
    de las dos b&#250;squedas de DNS mencionadas arriba falla para
    cualquiera de sus hosts virtuales. En algunos casos estas
    b&#250;squedas DNS puede que no est&#233;n bajo su control; por
    ejemplo, si <code>abc.dom</code> es uno de sus clientes y ellos
    controlan su propia DNS, pueden forzar a su servidor (pre-1.2) a
    fallar al iniciarse simplemente borrando el registro
    <code>www.abc.dom</code>.</p>

    <p>Otra formas pueden ser bastante m&#225;s complicadas. F&#237;jese
    en esta configuraci&#243;n:</p>

    <example>
      &lt;VirtualHost www.abc.dom&gt; <br />
      &#xA0;&#xA0;ServerAdmin webgirl@abc.dom <br />
      &#xA0;&#xA0;DocumentRoot /www/abc <br />
      &lt;/VirtualHost&gt; <br />
      <br />
      &lt;VirtualHost www.def.com&gt; <br />
      &#xA0;&#xA0;ServerAdmin webguy@def.com <br />
      &#xA0;&#xA0;DocumentRoot /www/def <br />
      &lt;/VirtualHost&gt;
    </example>

    <p>Suponga que ha asignado la direcci&#243;n 10.0.0.1 a
    <code>www.abc.dom</code> y 10.0.0.2 a
    <code>www.def.com</code>. Todav&#237;a m&#225;s, suponga que
    <code>def.com</code> tiene el control de sus propias DNS. Con esta
    configuraci&#243;n ha puesto <code>def.com</code> en una
    posici&#243;n en la que puede robar todo el trafico destinado a
    <code>abc.dom</code>. Para conseguirlo, todo lo que tiene que
    hacer es asignarle a <code>www.def.com</code> la direcci&#243;n
    10.0.0.1. Como ellos controlan sus propias DNS no puede evitar que
    apunten el registro <code>www.def.com</code> a donde quieran.</p>

    <p>Las peticiones dirigidas a la direcci&#243;n 10.0.0.1
    (inclu&#237;das aquellas en las los usuarios escriben URLs de tipo
    <code>http://www.abc.dom/whatever</code>) ser&#225;n todas
    servidas por el host virtual <code>def.com</code>. Comprender por
    qu&#233; ocurre esto requiere una discusi&#243;n m&#225;s profunda
    acerca de como Apache asigna las peticiones que recibe a los hosts
    virtuales que las servir&#225;n. Puede consultar <a
    href="vhosts/details.html">aqu&#237;</a> un documento que trata el
    tema.</p>
  </section>

  <section id="main">
    <title>La direcci&#243;n del "servidor principal"</title>

    <p>El que Apache soporte <a href="vhosts/name-based.html">hosting
    virtual basado en nombres</a> desde la version 1.1 hace que sea
    necesario que el servidor conozca la direcci&#243;n (o
    direcciones) IP del host que <program>httpd</program> est&#225;
    ejecutando. Para tener acceso a esta direcci&#243;n puede usar la
    directiva global <directive module="core">ServerName</directive>
    (si est&#225; presente) o llamar a la funci&#243;n de C
    <code>gethostname</code> (la cu&#225;l debe devolver el mismo
    resultado que devuelve ejecutar por l&#237;nea de comandos
    "hostname"). Entonces se produce una b&#250;squeda DNS de esa
    direcci&#243;n. Actualmente, no hay forma de evitar que se
    produzca esta b&#250;squeda.</p>

    <p>Si teme que esta b&#250;squeda pueda fallar porque su servidor
    DNS est&#225; desactivado entonces puede insertar el nombre de
    host en <code>/etc/hosts</code> (donde probablemente ya lo tiene
    para que la m&#225;quina pueda arrancar
    correctamente). Aseg&#250;rese de que su m&#225;quina est&#225;
    configurada para usar <code>/etc/hosts</code> en caso de que esa
    b&#250;squeda DNS falle. En funci&#243;n del sistema operativo que
    use, puede conseguir esto editando <code>/etc/resolv.conf</code>,
    o puede que <code>/etc/nsswitch.conf</code>.</p>

    <p>Si su servidor no tiene que ejecutar b&#250;squedas DNS por
    ninguna otra raz&#243;n entonces considere ejecutar Apache
    especificando el valor "local" en la variable de entorno
    <code>HOSTRESORDER</code>. Todo esto depende del sistema operativo
    y de las librer&#237;as de resoluci&#243;n que use. Esto
    tambi&#233;n afecta a los CGIs a menos que use
    <module>mod_env</module> para controlar el entorno. Por favor,
    consulte las p&#225;ginas de ayuda o la secci&#243;n de Preguntas
    M&#225;s Frecuentes de su sistema operativo.</p>
  </section>

  <section id="tips">
    <title>Consejos para evitar problemas</title>

    <ul>
      <li>
        use direcciones IP en 
        <directive module="core">VirtualHost</directive>
      </li>

      <li>
        use direcciones IP en
        <directive module="mpm_common">Listen</directive>
      </li>

      <li>
        aseg&#250;rese de que todos los host virtuales tienen
        expl&#237;citamente especificados una directiva <directive
        module="core">ServerName</directive>
      </li>

      <li>cree un servidor <code>&lt;VirtualHost _default_:*&gt;</code>
      que no tenga p&#225;ginas que servir.</li>
    </ul>
  </section>

  <section id="appendix">
    <title>Ap&#233;ndice: L&#237;neas de evoluci&#243;n de Apache</title>

    <p>La situaci&#243;n actual respecto a las b&#250;squedas DNS
    est&#225; lejos de ser la deseable. En Apache 1.2 se intent&#243;
    hacer que el servidor al menos se iniciara a pesar de que fallara
    la b&#250;squeda DNS, pero puede que esa no sea la mejor
    soluci&#243;n. En cualquier caso, requerir el uso de direcciones
    IP expl&#237;citas en los ficheros de configuraci&#243;n no es ni
    mucho menos una soluci&#243;n deseable con la situaci&#243;n
    actual de Internet, donde la renumeraci&#243;n es una
    necesidad.</p>

    <p>Una posible soluci&#243;n a los ataques de robo de servicio
    descritos m&#225;s arriba, ser&#237;a hacer una b&#250;squeda DNS
    inversa de la direcci&#243;n IP devuelta por la b&#250;squeda
    previa y comparar los dos nombres -- en caso de que sean
    diferentes, el host virtual se desactivar&#237;a. Esto
    requerir&#237;a configurar correctamente DNS inverso (una tarea
    con la que suelen estar familiarizados la mayor&#237;a de los
    administradores de sistemas).</p>

    <p>En cualquier caso, no parece posible iniciar en las condiciones
    apropiadas un servidor web alojado virtualmente cuando DNS ha
    fallado a no ser que se usen direcciones IP. Soluciones parciales
    tales como desactivar partes de la configuraci&#243;n podr&#237;an
    ser incluso peores que no iniciar el servidor en absoluto,
    dependiendo de las funciones que se espera que realice el servidor
    web.</p>

    <p>Como HTTP/1.1 est&#225; ampliamente extendido y los navegadores
    y los servidores proxy empiezan a usar la cabecera
    <code>Host</code>, en el futuro ser&#225; posible evitar el uso de
    hosting virtual basado en direcciones IP completamente. En ese
    caso, un servidor web no tiene ninguna necesidad de hacer
    b&#250;squedas de DNS durante la configuraci&#243;n. Sin embargo,
    en Marzo de 1997 esas funcionalidades no estaban lo
    suficientemente implantadas como para ponerlas en uso en
    servidores web que realizaban tareas de importancia
    cr&#237;tica.</p>
  </section>
</manualpage>

