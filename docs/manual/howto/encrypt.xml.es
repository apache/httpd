<?xml version='1.0' encoding='UTF-8' ?> <!DOCTYPE manualpage SYSTEM
"../style/manualpage.dtd"> <?xml-stylesheet type="text/xsl"
href="../style/manual.es.xsl"?> 
<!-- English Revision: 1860977 --> 
<!--
Spanish translation : Luis Joaquín Gil de Bernabé Pfeiffer 
lgilbernabe@apache.org --> 

<!--  Licensed
to the Apache Software Foundation (ASF) under one or more  contributor license
agreements.  See the NOTICE file distributed with  this work for additional
information regarding copyright ownership.  The ASF licenses this file to You
under the Apache License, Version 2.0  (the "License"); you may not use this
file except in compliance with  the License.  You may obtain a copy of the
License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
License for the specific language governing permissions and  limitations under
the License. -->

<manualpage metafile="encrypt.xml.meta"> <parentdocument href="./">How-To /
Tutoriales</parentdocument>

  <title>Cómo Cifrar su Tráfico</title>

  <summary> 
    <p>En esta guía se explica cómo hacer que su servidor Apache httpd
    use un cifrado para transferir datos entre el servidor y sus visitantes.
    En vez de usar enlaces http:, su sitio web usará https:, 
    si todo está configurado correctamente, toda persona que visite su web, tendrá
    más privacidad y protección.
    </p>
    <p>
    Este manual está pensado para aquellos que no están muy familiarizados con
    SSL/TLS y cifrados, junto con toda la jerga técnica incomprensible (Estamos bromeando, este tema es bastante importante, con serios expertos en el tema, y problemas reales que resolver - pero sí, suena a jerga técnica incomprensible para todos aquellos que no hayan tratado con esto). 
    Personas que han escuchado que su servidor http: no es del todo seguro a día de hoy. Que los espías y los malos están escuchando. Que incluso las empresas legítimas están poniendo datos en sus páginas web y vendiendo perfiles de visitantes. 
    </p> 
    <p>
    En esta guía nos centraremos en ayudarle a migrar su servidor httpd, para que deje de servir enlaces vía http: y los sirva vía https: sin necesidad de que te conviertas en un experto en SSL. Puede que te sientas fascinado con todas estas cosas de criptografía y estudies más sobre el tema y te conviertas en un experto de verdad. Pero también, puede que no esté  ejecutando un servidor web razonablemente seguro, y haga otras cosas buenas para la humanidad con tu tiempo.
    </p>
    <p>
    Obtendrá una idea aproximada de los roles, que estas cosas misteriosas denominadas "certificados" y el uso de "clave privada", como son usadas para que tus visitantes estén seguros de que contactan con tu servidor.
  <em>No</em> se comentará en esta documentación <em>cómo</em> funciona esto, 
  sólo cómo es utilizado: básicamente trataremos los pasaportes.
 </p>
  </summary> 
  <seealso><a href="../ssl/ssl_howto.html">SSL How-To</a></seealso>
  <seealso><a href="../mod/mod_ssl.html">mod_ssl</a></seealso> 
  <seealso><a href="../mod/mod_md.html">mod_md</a></seealso>

  <section id="protocol"> 
    <title>Pequeña introducción a los Certificados e.j: Pasaporte de Internet</title>
    <p> 
    El protocolo TLS (anteriormente conocido como SSL) es una forma en la que el servidor y el cliente pueden intercambiar información sin que nadie más intercepte las comunicaciones. Es lo que nuestros navegadores entienden cuando abrimos un enlace <em>https</em>.
   </p> 
   <p> 
    Adicionalmente para tener una conversación privada entre entre el servidor y el cliente, nuestro navegador también necesita saber que está hablando con el servidor legitimo, y no con otro que se esté haciendo pasar por él.
    Esto, después del cifrado, es la otra parte del protocolo TLS.
  </p>
  <p>
   Para que tu servidor pueda hacer esto, no sólo necesita el software para
   TLS, ej.: el módulo <module>mod_ssl</module>, si no también alguna prueba
   de identidad en Internet. A esto nos referimos comúnmente como <em>certificado</em>.
   Básicamente, todos tenemos el mismo <module>mod_ssl</module> y con él, podemos
   cifrar, pero solamente tú tienes <em>tu</em> certificado, y con él, tú eres tú.
   Es decir es una prueba de identidad de quien es, en este caso, el servidor.
 </p>
 <p> 
  Un certificado es la equivalencia a un pasaporte. Contiene dos cosas:
  Un sello de aprobación de la persona que ha expedido el pasaporte, y una referencia
  a tus huellas digitales, ej.: Lo que se llama <em>clave privada</em> en términos de cifrado.
  </p>
  <p>
  	Cuando se configura Apache httpd para que use enlaces https, necesitas dotarlo de un certificado y su clave privada. Si esta clave privada no es desvelada
  	a nadie, sólo tú podrás probar que dicho certificado te pertenece. En ese sentido, un navegador hablando con el servidor por segunda vez, puede reconocer que es
  	sin duda el mismo servidor con el que se ha estado comunicando previamente.
    </p>
    <p>
    	Pero, ¿cómo se sabe que es un servidor legítimo la primera vez que se 
    	comunica con alguien? Aquí es donde entra en juego el sello digital. 
    	Este sello digital lo crea otra entidad o autoridad, utilizando su propia
    	clave privada. Esta entidad o autoridad, también tiene su propio certificado 
    	ej.: su propio pasaporte. El navegador puede asegurarse de que este 
    	pasaporte se basa en la misma clave que se usó para su sello digital.
    	Ahora, a parte de comprobar si el de nuestro servidor es correcto, también tiene
    	que asegurarse que el pasaporte de la entidad o autoridad del sello
    	de <em>nuestro</em> pasaporte es correcta.
    </p>
    <p>
    	Y ese pasaporte, también esta sellado digitalmente por otro con un certificado y una clave. Por lo que el navegador sólo tendrá que cerciorarse de que <em>ese</em> es un certificado correcto.
    </p>
    <p>
    Y ese pasaporte, tendrá también un sello de identidad digital emitido por otro tercero con su clave y su certificado. Por lo tanto, el navegador sólo tendrá que cerciorarse que <em>ese</em> es el correcto, para confiar en el que ofrece nuestro servidor. Este juego de confianza puede llegar desde unos pocos a varios niveles (normalmente menos de 5).
    </p>
    <p>
    Al final, el navegador va ha encontrarse con un certificado sellado con su propia clave. Es un certificado, que como diría Gloria Gaynor, dice "Soy lo que soy". El navegador entonces decidirá si confiar o no en él. Si no, su servidor no será de confianza. De lo contrario, lo será. Así de simple.
    </p>
    <p>
    Esta comprobación de confianza para Gloria Gaynor en Internet, es fácil: tu navegador (o tu sistema operativo) vienen con una lista de pasaportes en los cuales confiar, es decir preinstalados. En caso de encontrar el certificado de Gloria en la lista, se confiará o no en él. 
    </p>
    <p>
    Todo esto funcionará correctamente siempre y cuando cada cual mantenga su clave privada para sí, y no la comparta ni publique. 
    Ya que cualquiera que obtenga dicha clave privada, puede suplantar a la entidad o persona propietaria de dicha clave. Y si el propietario de dicha clave puede firmar certificados (validarlos) el impostor también podrá hacer eso. Así que todos los pasaportes que haya sellado el impostor, serán 100% válidos, e indistinguibles de los reales.
    </p>
    <p>
    Este modelo funciona, pero tiene sus limitaciones. Es por eso que los desarrolladores de los navegadores están tan interesados en tener una lista con la correcta Gloria Gaynor, y amenazan con expulsar a cualquiera que sea descuidado con su clave. 
    </p>
</section>

<section id="buycert"> <title>Comprar un Certificado</title>
  <p> 
    Puedes comprar uno. Hay muchas compañías vendiendo pasaportes de 
  	Internet (certificados) como servicio. En <a href="https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReport">esta lista de Mozilla,</a> podrás encontrar todas las compañías en las que el  navegador Firefox confía. Escoge una, visita su página web y te dirán los diferentes precios, y cómo hacer para demostrar que eres quien dices ser, y así podrán marcar tu certificado con un sello de confianza.
  </p>

   <p>
   	Todos tienen sus propios métodos,también dependiendo de qué tipo de pasaporte pidas, puedes configurarlo normalmente a base de clics en su web. Una vez que hayas terminado te enviarán un email con los pasos siguientes. Al fin y al cabo ellos te enseñarán como generar tu propio certificado, así como tu propia clave privada y ellos te expedirán un certificado sellado que coincida.
  </p>  
   <p>Finalmente tendrás que poner tu clave en un fichero y tu certificado en otro. Ponerlos en tu servidor, cerciorarte de que solo un usuario de confianza tiene acceso a estos ficheros (comprobando los permisos), y que dicho usuario pueda añadirlo a la configuración de httpd. Todo esto se describe en <a href="../ssl/ssl_howto.html">SSL How-To</a>.     
</p>     
<p>     
</p>
</section>

    <section id="freecert">
    <title>Obtener un Certificado Gratuito</title>
    <p>
    	También hay compañías que ofrecen certificados para servidores web 
    	totalmente gratuitos. La empresa pionera en esto es 
    	<a href="https://letsencrypt.org">Let's Encrypt</a>que es un servicio de
    	 la organización sin animo de lucro
    <a href="https://www.abetterinternet.org/">Internet Security Research Group (ISRG)</a>, 
    para "reducir las barreras financieras, tecnológicas y educacionales para 
    securizar las comunicaciones en Internet"
    </p>

    <p>
    	No sólo ofrecen certificados, también han desarrollado una interfaz que
    	puede ser usada con tu Apache httpd para obtener un certificado. Es
    	aquí donde cabe mencionar a <module>mod_md</module>
    </p>
    <p>
    (Puedes alejar el zoom y mirar cómo se configuran el módulo <module>mod_md</module> y 
    los <a href="https://httpd.apache.org/docs/2.4/vhosts/">hosts virtuales</a>...)
    </p>
  </section>
</manualpage>
