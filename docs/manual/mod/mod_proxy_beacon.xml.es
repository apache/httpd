<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
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

<modulesynopsis metafile="mod_proxy_beacon.xml.meta">

<name>mod_proxy_beacon</name>
<description>Membresía dinámica de balanceador en la que los backends se
anuncian a sí mismos al proxy inverso mediante datagramas UDP unicast</description>
<status>Extension</status>
<sourcefile>mod_proxy_beacon.c</sourcefile>
<identifier>proxy_beacon_module</identifier>
<compatibility>Disponible en Apache 2.5 y posteriores</compatibility>

<summary>
    <p>Este módulo permite que los servidores backend se <em>anuncien a sí
    mismos</em> a un proxy inverso de cara al cliente, que entonces añade cada
    backend anunciante como un miembro activo (worker) de un balanceador de
    <module>mod_proxy_balancer</module>. Cuando un backend deja de anunciarse,
    el proxy lo retira de la rotación. Esto proporciona una membresía de
    balanceador autorregistrada y autorreparable sin editar la configuración
    del proxy ni manejar el <code>balancer-manager</code> manualmente.</p>

    <p>La comunicación usa datagramas <strong>UDP unicast</strong> simples (no
    multicast, que se filtra en la mayoría de redes y no atraviesa Internet
    pública). Los datos fluyen del backend al proxy:</p>

    <ul>
      <li>El proxy inverso enlaza un socket UDP y <em>recibe</em> en una
          dirección estable (<directive>ProxyBeaconListen</directive>).</li>
      <li>Cada backend envía periódicamente (<em>sends</em>) un breve
          datagrama de anuncio al proxy
          (<directive>ProxyBeaconAddress</directive>), anunciando su propia
          URL enrutable (<directive>ProxyBeaconAdvertise</directive>).</li>
    </ul>

    <p>Los datagramas son de "disparar y olvidar": un anuncio perdido se
    recupera con el siguiente anuncio periódico, y el reordenamiento se
    rechaza mediante una comprobación de marca temporal por backend, por lo
    que no se necesita ninguna capa de conexión, reconexión o enmarcado.</p>

    <p>En el proxy, <directive>ProxyBeaconBalancer</directive> nombra el
    balanceador al que se añaden los backends anunciados. Los cambios de
    membresía se aplican usando el mismo mecanismo interno que la interfaz
    web <code>balancer-manager</code>, de modo que un backend añadido de esta
    forma se comporta exactamente como un
    <directive module="mod_proxy">BalancerMember</directive> configurado de
    forma estática o añadido manualmente, y es visible y editable en el
    <code>balancer-manager</code>.</p>

    <p>Este módulo <em>requiere</em> el servicio de
    <module>mod_watchdog</module> y <module>mod_proxy_balancer</module>. El
    trabajo en segundo plano (escuchar, publicar, añadir y expulsar miembros)
    se ejecuta en un único proceso hijo de <module>mod_watchdog</module>, por
    lo que no está disponible bajo el comportamiento del MPM
    <code>prefork</code>, donde ese singleton no puede ejecutarse.</p>

<note type="warning"><title>Autenticación</title>
    <p>Cualquier host que pueda alcanzar el puerto de recepción del proxy
    podría, de otro modo, anunciar una URL de backend arbitraria y hacer que
    el proxy envíe tráfico de cliente a ella (y una dirección de origen UDP
    es trivialmente falsificable).
    <directive>ProxyBeaconSecret</directive> es por tanto
    <strong>obligatoria</strong>: debe establecerse con el mismo valor en el
    proxy y en cada backend, y el servidor no arranca si algún servidor
    participante la omite. Los anuncios se autentican con un código de
    autenticación de mensaje con clave (MAC) y una marca temporal, y el proxy
    descarta cualquier anuncio que no esté válidamente firmado y sea
    reciente. No existe un modo sin autenticación.</p>
</note>

<note><title>Confidencialidad</title>
    <p>Los anuncios se autentican pero no se cifran; la carga útil son
    metadatos operativos (URLs de backend), no datos secretos. La
    confidencialidad del transporte (por ejemplo, DTLS) no se proporciona
    actualmente y sería una capa futura independiente.</p>
</note>

</summary>
<seealso><module>mod_proxy</module></seealso>
<seealso><module>mod_proxy_balancer</module></seealso>
<seealso><module>mod_proxy_hcheck</module></seealso>
<seealso><module>mod_watchdog</module></seealso>

<section id="examples">
    <title>Ejemplo de uso</title>

    <p>El siguiente par de configuraciones establece un balanceador
    autorregistrado. Los backends no necesitan conocerse entre sí y el proxy
    no necesita entradas
    <directive module="mod_proxy">BalancerMember</directive> predeclaradas
    &mdash; solo un balanceador vacío con espacio para crecer.</p>

    <p>En el <strong>proxy inverso</strong>:</p>
    <highlight language="config">
# Recibir anuncios de backend en la interfaz de red del clúster (UDP).
ProxyBeaconListen 0.0.0.0:5555
ProxyBeaconSecret    "hex:00112233445566778899aabbccddeeff"
ProxyBeaconBalancer  cluster

# Un backend se retira de la rotación si no se anuncia durante 30 segundos.
ProxyBeaconTimeout   30

# Un balanceador inicialmente vacío con espacio libre para los miembros dinámicos.
&lt;Proxy balancer://cluster&gt;
  ProxySet growth=16
&lt;/Proxy&gt;
ProxyPass        "/" "balancer://cluster/"
ProxyPassReverse "/" "balancer://cluster/"
    </highlight>

    <p>En cada servidor <strong>backend</strong>:</p>
    <highlight language="config">
# Anunciar el origen enrutable de este backend al proxy cada 10 segundos (UDP).
ProxyBeaconAddress   proxy.example.com:5555
ProxyBeaconAdvertise http://10.0.0.5:8080
ProxyBeaconSecret    "hex:00112233445566778899aabbccddeeff"
ProxyBeaconInterval  10
    </highlight>

    <p>Cuando un backend arranca, comienza a enviar anuncios. El proxy
    verifica cada anuncio contra el secreto compartido, añade
    <code>http://10.0.0.5:8080</code> como miembro de
    <code>balancer://cluster</code>, y lo habilita. Si ese backend deja
    después de anunciarse durante más tiempo que
    <directive>ProxyBeaconTimeout</directive>, el proxy deshabilita el
    miembro (retirándolo de la rotación); un anuncio posterior lo vuelve a
    habilitar.</p>

    <note>
    <p>Un backend añadido en tiempo de ejecución ocupa uno de los huecos de
    crecimiento del balanceador durante toda la vida del proceso del
    servidor; se deshabilita en lugar de eliminarse cuando deja de
    anunciarse, igualando el comportamiento del <code>balancer-manager</code>
    (que puede añadir, pero no eliminar, workers en tiempo de ejecución).
    Dimensione <code>growth</code> para el número máximo de backends que
    espera que se registren.</p>
    </note>

</section>

<section id="identity"><title>Identidad de los miembros</title>

    <p>Una URL anunciada identifica un <em>origen</em> de backend:
    <code>scheme://host[:port]</code>, y nada más. El proxy usa la misma
    cadena como identidad del miembro en todas partes: como la clave bajo la
    que rastrea el estado de lease y de repetición del backend, y como el
    nombre de worker que crea en el balanceador. Para mantener esas
    identidades iguales, el proxy:</p>
    <ul>
      <li><strong>canonicaliza</strong> cada URL anunciada: el esquema y el
          host se pasan a minúsculas, se elimina el puerto por defecto del
          esquema (<code>HTTP://Backend.Example.com:80</code> y
          <code>http://backend.example.com</code> son el mismo miembro), y se
          ignora una única <code>/</code> final;</li>
      <li><strong>descarta</strong> cualquier anuncio que no sea un origen:
          uno que lleve una ruta (distinta de <code>/</code>), una cadena de
          consulta, un fragmento, información de usuario, un puerto no
          válido (como <code>0</code>), la forma de socket
          <code>unix:</code>, un esquema demasiado largo para almacenarse
          como parte de un worker, o un nombre de host demasiado largo para
          almacenarse. El descarte se registra (con limitación de tasa) como
          <code>unacceptable url</code> y el backend no se añade.</li>
    </ul>

    <p>Los errores que ningún cambio posterior en la red puede corregir se
    informan mediante <code>httpd -t</code> además de en el arranque: una
    <directive>ProxyBeaconSecret</directive> ausente, una
    <directive>ProxyBeaconAddress</directive> que no sea
    <code>host:port</code>, una dirección
    <directive>ProxyBeaconListen</directive> malformada, y una
    <directive>ProxyBeaconBalancer</directive> que no esté definida para el
    servidor. No se comprueba entonces si una dirección se resuelve o si un
    puerto puede enlazarse; el proxy sigue reintentándolo.</p>

    <p>Las rutas se rechazan porque el balanceador encuentra un miembro por
    coincidencia del prefijo más largo. Los anuncios para
    <code>http://10.0.0.5:8080/one</code> y
    <code>http://10.0.0.5:8080/one/two</code> se rastrearían como dos
    miembros con leases separados pero se resolverían a un único worker, por
    lo que la caducidad de un lease podría deshabilitar un worker cuyo otro
    lease aún estuviera vigente. Elija las rutas de petición en el proxy con
    <directive module="mod_proxy">ProxyPass</directive>, no mediante la URL
    anunciada.</p>

    <p>Se confirma que un backend anunciado con éxito existe en el
    balanceador antes de informar de que se ha añadido, habilitado o
    expulsado; un anuncio que el proxy no puede convertir en un miembro se
    registra y se reintenta tras una espera creciente en lugar de
    comunicarse como un éxito.</p>

</section>

<section id="ownership"><title>Propiedad y traspaso del watchdog</title>

    <p>Cada worker que <module>mod_proxy_beacon</module> crea se marca con el
    estado <code>Bcn</code> (indicador <code>B</code>), que se almacena en el
    estado compartido del worker y se muestra en el <code>balancer-manager</code>.
    El módulo solo habilita o expulsa workers que lleven esta marca. Un
    worker con el mismo nombre que no la lleve &mdash; un
    <directive module="mod_proxy">BalancerMember</directive> de la
    configuración, o uno añadido por un administrador &mdash; se deja en paz;
    un anuncio para él se descarta y se registra como
    <code>member not managed by beacon</code>.</p>

    <p>Los anuncios se reciben y los leases se mantienen mediante un único
    proceso hijo de <module>mod_watchdog</module>. Si ese proceso termina o es
    matado, el singleton del watchdog se traslada a otro hijo, que arranca
    sin registro de los miembros que él mismo no añadió. Cuando un hijo se
    convierte en propietario, por tanto <em>toma el control</em> de todos los
    workers del balanceador que lleven la marca <code>Bcn</code> (registrado
    como <code>took over <var>N</var> existing member(s)</code>):</p>
    <ul>
      <li>cada miembro del que se toma el control recibe un lease nuevo a
          partir de ese momento, de modo que un miembro que desde entonces
          ha quedado en silencio se expulsa
          <directive>ProxyBeaconTimeout</directive> después del traspaso en
          lugar de permanecer habilitado indefinidamente;</li>
      <li>un miembro que ya está deshabilitado se trata como expulsado, y su
          siguiente anuncio lo vuelve a habilitar.</li>
    </ul>

    <note>
    <p>Un backend muerto puede por tanto permanecer en rotación hasta un
    <directive>ProxyBeaconTimeout</directive> después de un traspaso. La
    marca de agua alta de repetición por miembro tampoco se traslada: durante
    el traspaso, un anuncio capturado que todavía esté dentro de la ventana
    de frescura de <directive>ProxyBeaconMaxSkew</directive> puede repetirse
    una vez por miembro, lo que renueva el lease de ese miembro durante un
    tiempo de espera. No permite añadir un nuevo miembro sin el secreto
    compartido.</p>
    </note>

    <p>Un nuevo propietario solo puede arrancar una vez que el mutex de
    callback del watchdog haya sido liberado por el proceso que lo poseía. Si
    el mecanismo de mutex por defecto se libera cuando su poseedor es matado
    depende de la plataforma; si el traspaso rápido tras un fallo es
    importante, seleccione un mecanismo que se libere al morir el proceso
    para el mutex <code>watchdog-callback</code> con la directiva
    <directive module="core">Mutex</directive> (por ejemplo,
    <code>Mutex sysvsem watchdog-callback</code>).</p>

</section>

<section id="operator"><title>Control administrativo de los miembros</title>

    <p>Beacon usa el indicador de estado <code>Disabled</code> para retirar
    un miembro de la rotación cuando su lease caduca, y lo elimina cuando el
    miembro vuelve a anunciarse; posee ese indicador para los miembros que
    gestiona. Un administrador que deshabilita uno de esos miembros en el
    <code>balancer-manager</code> es por tanto sobrescrito por el siguiente
    anuncio tras una expulsión.</p>

    <p>Para mantener un miembro fuera de rotación independientemente de lo
    que anuncie, póngalo en <code>Stopped</code> o <code>Drain</code> en su
    lugar. Beacon nunca cambia esos indicadores, ni el indicador establecido
    por una comprobación de salud activa (<module>mod_proxy_hcheck</module>);
    se combinan con el estado del lease, de modo que un miembro detenido
    permanece detenido a través de cualquier número de expulsiones y
    reactivaciones.</p>

</section>

<section id="limits"><title>Validación de mensajes y límites</title>

    <p>El receptor valida cada datagrama antes de actuar sobre él:</p>
    <ul>
      <li>el datagrama debe caber en 2048 bytes y no debe contener un byte
          NUL; uno más largo se descarta en lugar de truncarse;</li>
      <li>se verifica el MAC, tanto si <directive>ProxyBeaconBalancer</directive>
          está establecida como si no, de modo que incluso el modo
          solo-de-registro registra únicamente anuncios autenticados;</li>
      <li>el mensaje autenticado debe tener la forma exacta
          <code>BEACON key=value key=value ... mac=...</code> (espacios
          simples, campos conocidos sin repetir), y <code>ts=</code> debe ser
          un número decimal sencillo de como máximo 18 dígitos;</li>
      <li>la url debe ser un origen ASCII imprimible (consulte
          <a href="#identity">Identidad de los miembros</a>).</li>
    </ul>

    <p>El proxy rastrea como máximo 256 URLs anunciadas. Un registro se
    libera una vez que pertenece a un miembro expulsado, o a una adición que
    falló, y ha permanecido en silencio durante más del doble de
    <directive>ProxyBeaconMaxSkew</directive> (para entonces una repetición de
    su último mensaje sería obsoleta de todos modos, así que no se pierde
    ninguna protección frente a repeticiones). Hasta entonces, una avalancha
    de URLs distintas procedentes de alguien que posea el secreto puede
    llenar la tabla y mantener fuera a los nuevos backends; los miembros en
    sí permanecen en el balanceador, y un backend que vuelve a anunciarse
    después de que su registro se liberó se readopta. Un límite propio del
    balanceador (<code>growth</code>, como máximo 100) limita cuántos
    miembros pueden llegar a añadirse.</p>

    <p>Si el socket UDP no puede abrirse (una dirección que no se resuelve,
    un puerto en uso), la apertura se reintenta con un retardo que empieza en
    30 segundos y se duplica hasta 10 minutos. Lo mismo ocurre tras cinco
    envíos o recepciones fallidos consecutivos. Un backend busca de nuevo la
    dirección del proxy cada cinco minutos, conservando la que tiene si eso
    falla, de modo que un proxy que se ha trasladado se encuentra sin
    necesidad de un reinicio. Las búsquedas de nombres son síncronas y se
    ejecutan en el único hilo de <module>mod_watchdog</module> que sirve a
    todas las configuraciones de beacon del servidor, por lo que un nombre
    que no se resuelve puede bloquearlas durante todo el tiempo que el
    resolutor tarde en rendirse. Prefiera una dirección IP en
    <directive>ProxyBeaconAddress</directive> y
    <directive>ProxyBeaconListen</directive>.</p>

    <p>Cada vez que el watchdog se ejecuta, el proxy lee datagramas durante
    como máximo 50 milisegundos (y como máximo 1024 de ellos), de modo que
    una avalancha no pueda impedirle expulsar miembros; lo que no lee a
    tiempo espera en el búfer del socket o es descartado por el sistema
    operativo. Se registran como máximo veinte líneas <code>received:</code>
    por segundo para cada configuración; el número omitido se registra
    cuando llega el siguiente anuncio después de ese segundo.</p>

</section>

<section id="envelope"><title>Para qué sirve este módulo</title>

    <p>El módulo proporciona <em>membresía basada en actividad</em> para un
    conjunto de backends que usted controla. Úselo dentro de estos límites,
    que son propiedades del diseño y no defectos que haya que evitar:</p>

    <ul>
      <li><strong>Identidades de origen estables.</strong> Un miembro que
          deja de anunciarse se deshabilita, no se elimina, y conserva su
          hueco en el balanceador durante toda la vida del servidor (consulte
          <a href="#operator">Control administrativo de los miembros</a>).
          Una flota cuyos backends cambian de dirección o puerto con el
          tiempo agota <code>growth</code> con cada nuevo origen, incluso
          cuando los antiguos ya no existen; cuando se agota, se rechazan los
          recién llegados. Dimensione <code>growth</code> para el número de
          <em>orígenes distintos</em> que lleguen a anunciarse entre
          reinicios, y vigile el registro por si hay adiciones rechazadas. No
          es adecuado para direcciones que rotan de forma arbitraria.</li>
      <li><strong>Un único dominio de confianza.</strong> El secreto es una
          credencial de membresía: cualquier poseedor puede anunciar
          cualquier origen alcanzable, incluso en lugar de otro backend. No
          lo comparta entre cargas de trabajo que no confíen entre sí
          (consulte
          <directive module="mod_proxy_beacon">ProxyBeaconSecret</directive>).</li>
      <li><strong>Actividad, no disponibilidad.</strong> Un backend se
          anuncia mientras su watchdog se ejecuta. Eso no dice nada sobre si
          puede atender una petición. Un nuevo miembro se habilita en cuanto
          se acepta su primer anuncio; combine el módulo con
          <module>mod_proxy_hcheck</module> o con el propio control de los
          backends sobre cuándo empiezan a anunciarse si eso le importa.</li>
      <li><strong>La protección frente a repeticiones pertenece al
          propietario.</strong> El registro de la última marca temporal
          aceptada de cada miembro lo mantiene el proceso que posee el
          watchdog. Después de que cambie el propietario, o de que el
          servidor se reinicie, un anuncio capturado que aún esté dentro de
          la ventana de <directive>ProxyBeaconMaxSkew</directive> puede
          aceptarse una vez más (consulte
          <a href="#ownership">Propiedad y traspaso del watchdog</a>).
          Mantenga el puerto receptor en una red a la que no puedan llegar
          hosts no confiables, ya que el secreto no es una defensa contra una
          repetición.</li>
      <li><strong>Un receptor por backend.</strong> Un backend se anuncia a
          una única dirección (<directive>ProxyBeaconAddress</directive>).
          Anunciarse a varios proxies no es algo que el módulo ofrezca.</li>
      <li><strong>Unicast, misma red.</strong> Los datagramas no se cifran ni
          se confirman.</li>
    </ul>

</section>

<directivesynopsis>
<name>ProxyBeaconListen</name>
<description>Dirección en la que el proxy inverso recibe los beacons de
backend</description>
<syntax>ProxyBeaconListen [<em>address</em>][:<em>port</em>]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyBeaconListen</directive> marca un
    servidor como el <em>receptor</em> de beacon (el proxy inverso). Enlaza
    un socket UDP a la dirección dada, por ejemplo
    <code>0.0.0.0:5555</code> para recibir en todas las interfaces. Se acepta
    e ignora un esquema inicial (como <code>tcp://</code>).</p>

    <p>La dirección y el puerto son ambos opcionales y, cuando se omiten, se
    heredan de la propia dirección y puerto de este servidor (su
    <directive module="core">Listen</directive>/<directive
    module="core">ServerName</directive>). Sin ningún argumento, el listener
    de beacon enlaza la propia dirección y puerto del servidor; dando solo
    una dirección hereda el puerto, y así sucesivamente. Dado que UDP y TCP
    son espacios de puertos independientes, enlazar el socket de beacon al
    puerto del servidor <em>no</em> colisiona con el listener TCP del
    servidor &mdash; permitiendo que el canal de beacon comparta el punto
    final del servicio, lo que además identifica el proxy a los backends por
    su dirección real. (El listener se enlaza en un hijo sin privilegios, por
    lo que un puerto privilegiado como el 80 o el 443 no puede compartirse de
    esta forma; use el puerto del servidor solo cuando no sea
    privilegiado.)</p>

    <p>Los backends envían a esta dirección mediante
    <directive>ProxyBeaconAddress</directive>. La directiva debe usarse junto
    con <directive>ProxyBeaconBalancer</directive>; sin ella, los anuncios se
    reciben y registran pero no se añade ningún miembro.
    <directive>ProxyBeaconListen</directive> y
    <directive>ProxyBeaconAddress</directive> son mutuamente excluyentes en
    el mismo servidor.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyBeaconAddress</name>
<description>Dirección del proxy inverso al que un backend envía sus
anuncios</description>
<syntax>ProxyBeaconAddress <em>address:port</em></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyBeaconAddress</directive> marca un
    servidor como un <em>emisor</em> de anuncios (un backend). Envía
    datagramas UDP a la dirección <directive>ProxyBeaconListen</directive>
    del proxy, dada por <em>address:port</em>, por ejemplo
    <code>proxy.example.com:5555</code> (se acepta e ignora un esquema inicial
    como <code>tcp://</code>). Dado que UDP no tiene conexión, un backend
    puede arrancar antes de que el proxy esté disponible: los primeros
    datagramas simplemente se descartan y el siguiente intervalo lo
    reintenta.</p>

    <p>Use <directive>ProxyBeaconAdvertise</directive> para especificar la
    URL enrutable que anuncia el backend.
    <directive>ProxyBeaconAddress</directive> y
    <directive>ProxyBeaconListen</directive> son mutuamente excluyentes en el
    mismo servidor.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyBeaconAdvertise</name>
<description>La URL enrutable que un backend anuncia al proxy inverso</description>
<syntax>ProxyBeaconAdvertise <em>url</em></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyBeaconAdvertise</directive> establece el
    propio origen alcanzable del backend (por ejemplo
    <code>http://10.0.0.5:8080</code>) que el proxy añadirá como un
    <directive module="mod_proxy">BalancerMember</directive>. Debe ser una URL
    <code>scheme://host[:port]</code> completa que el proxy pueda alcanzar
    &mdash; no la dirección de escucha local &mdash; y se valida al analizar
    la configuración. La URL nombra únicamente un <em>origen</em>: una ruta,
    cadena de consulta, fragmento o información de usuario se rechazan con
    un error de configuración (consulte
    <a href="#identity">Identidad de los miembros</a>). La URL se anuncia en
    su forma canónica.</p>

    <p>Esta directiva se usa en un backend, junto con
    <directive>ProxyBeaconAddress</directive>. Si se omite, el backend sigue
    enviando un latido pero no anuncia ninguna URL, de modo que el proxy
    registra el anuncio sin añadir un miembro.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyBeaconBalancer</name>
<description>Nombre del balanceador al que se añaden los backends anunciados</description>
<syntax>ProxyBeaconBalancer <em>name</em></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyBeaconBalancer</directive> nombra el
    balanceador, en el proxy inverso, en el que se insertan como miembros los
    backends anunciados. Indique el nombre desnudo del balanceador (por
    ejemplo, <code>cluster</code> para <code>balancer://cluster</code>); se
    acepta y elimina un <code>balancer://</code> inicial.</p>

    <p>El balanceador nombrado debe existir y tener capacidad libre.
    Declárelo con un bloque
    <directive module="mod_proxy">&lt;Proxy&gt;</directive> y un ajuste
    <code>growth</code> (o confíe en
    <directive module="mod_proxy">BalancerGrowth</directive>) para que haya
    huecos libres para los miembros añadidos dinámicamente. Esta directiva se
    usa junto con <directive>ProxyBeaconListen</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyBeaconInterval</name>
<description>Con qué frecuencia un backend publica su anuncio</description>
<syntax>ProxyBeaconInterval <em>interval</em></syntax>
<default>ProxyBeaconInterval 5</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyBeaconInterval</directive> establece con
    qué frecuencia un backend (un servidor
    <directive>ProxyBeaconAddress</directive>) publica su anuncio. Usa la
    sintaxis de directiva
    <a href="directive-dict.html#Syntax">time-interval</a> y por defecto son
    segundos; el valor por defecto es 5 segundos.</p>

    <p>El intervalo debe ser significativamente menor que el
    <directive>ProxyBeaconTimeout</directive> del proxy, de modo que la
    pérdida o el retraso ocasional de un anuncio no provoque que se expulse
    un backend saludable.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyBeaconTimeout</name>
<description>Cuánto tiempo espera el proxy, sin un anuncio, antes de retirar
un backend de la rotación</description>
<syntax>ProxyBeaconTimeout <em>interval</em></syntax>
<default>ProxyBeaconTimeout 0</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyBeaconTimeout</directive> establece
    cuánto tiempo esperará el proxy inverso un anuncio de un backend antes de
    deshabilitar el miembro del balanceador de ese backend (retirándolo de la
    rotación). Un anuncio posterior del mismo backend lo vuelve a habilitar.
    Usa la sintaxis de directiva
    <a href="directive-dict.html#Syntax">time-interval</a> y por defecto son
    segundos.</p>

    <p>El valor por defecto, <code>0</code>, deshabilita por completo la
    expulsión: los backends se añaden cuando se anuncian pero nunca se
    eliminan automáticamente. Establezca esto a un pequeño múltiplo del
    <directive>ProxyBeaconInterval</directive> de los backends para habilitar
    una membresía autorreparable. Esta directiva se usa en el proxy.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyBeaconSecret</name>
<description>Secreto precompartido usado para autenticar los anuncios</description>
<syntax>ProxyBeaconSecret <em>secret</em>|hex:<em>key</em></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyBeaconSecret</directive> establece un
    secreto de clúster precompartido. Debe configurarse con el
    <em>mismo</em> valor en el proxy inverso y en cada backend. El backend
    (emisor) firma cada anuncio con un código de autenticación de mensaje con
    clave (un MAC SipHash) derivado del secreto, junto con una marca
    temporal; el proxy (receptor) recalcula el MAC y comprueba la marca
    temporal, descartando cualquier anuncio que esté falsificado, manipulado
    o repetido. Los mensajes repetidos se detectan de dos formas: una ventana
    de frescura (<directive>ProxyBeaconMaxSkew</directive>) rechaza marcas
    temporales antiguas, y una comprobación por backend rechaza cualquier
    anuncio cuya marca temporal no avance estrictamente, de modo que un
    mensaje capturado y reenviado (por ejemplo, uno repetido para evitar que
    se expulse a un backend muerto) se descarta.</p>

    <p>Esta directiva es <strong>obligatoria</strong> en todo servidor que
    participe en el canal de beacon &mdash; el proxy
    (<directive>ProxyBeaconListen</directive>) y cada backend
    (<directive>ProxyBeaconAddress</directive>). Si alguno de esos
    servidores la omite, el servidor no arranca; no existe un modo sin
    autenticación.</p>

    <p>Todo anuncio debe llevar un MAC válido y reciente o se rechaza. Si los
    secretos del proxy y de un backend difieren, los anuncios de ese backend
    se rechazan silenciosamente (y se registran), lo que aparece como que el
    backend nunca se une al balanceador.</p>

    <p>Use una clave aleatoria. Genere una con
    <code>openssl rand -hex 16</code> y configúrela como <code>hex:</code>
    seguido de los 32 dígitos hexadecimales; ese valor se usa directamente
    como la clave MAC de 128 bits, de modo que no hay nada que adivinar.
    Cualquier otro valor se trata como una frase de contraseña: debe tener al
    menos 16 caracteres, y la clave MAC se deriva de ella con un hash rápido.
    Dado que la etiqueta de autenticación tiene 64 bits, cualquiera que
    capture un único anuncio puede probar suposiciones de la frase de
    contraseña fuera de línea a máxima velocidad, de modo que una frase de
    contraseña protege solo tan bien como de aleatoria y larga sea. Un valor
    que empieza por <code>hex:</code> siempre se interpreta como una clave y
    se rechaza si no tiene exactamente 32 dígitos hexadecimales.</p>

    <note type="warning"><title>El secreto es una credencial de membresía</title>
    <p>Un MAC válido solo demuestra que el emisor posee el secreto. No
    demuestra que el emisor sea propietario de la URL que anuncia, que pueda
    hablar en nombre de otro backend, o que esté listo para servir. Todo
    poseedor puede por tanto registrar cualquier origen de backend que el
    proxy pueda alcanzar, anunciarse en nombre de otros miembros (manteniendo
    vivos sus leases), y agotar los huecos de crecimiento del balanceador y
    la tabla de seguimiento. Trate el secreto como una credencial de
    administrador para el balanceador, y compártala solo entre hosts en los
    que confiaría con ese nivel. No es una frontera entre cargas de trabajo
    parcialmente confiables.</p>
    </note>

    <p>Dado que el secreto se almacena en el archivo de configuración,
    restrinja los permisos de ese archivo como lo haría para una clave
    privada.</p>

    <note><title>Sincronización de relojes</title>
    <p>La protección frente a repeticiones basada en marcas temporales
    compara la hora del anuncio con el reloj del proxy, por lo que el proxy y
    los backends deben tener relojes razonablemente sincronizados (por
    ejemplo, mediante NTP). Consulte
    <directive>ProxyBeaconMaxSkew</directive>.</p>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyBeaconMaxSkew</name>
<description>Antigüedad máxima permitida de un anuncio firmado</description>
<syntax>ProxyBeaconMaxSkew <em>interval</em></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>ProxyBeaconMaxSkew</directive> establece la
    ventana antirrepetición usada cuando se configura
    <directive>ProxyBeaconSecret</directive>: el proxy rechaza cualquier
    anuncio cuya marca temporal firmada difiera de la hora actual en más de
    esta cantidad, en cualquier dirección. Usa la sintaxis de directiva
    <a href="directive-dict.html#Syntax">time-interval</a> y por defecto son
    segundos.</p>

    <p>Si no se establece, el valor por defecto es 30 segundos. Se respetan
    los valores inferiores al segundo (por ejemplo, <code>500ms</code>). Una
    ventana más grande tolera un mayor desajuste de reloj entre hosts; una
    ventana más pequeña acota la comprobación de frescura. Tenga en cuenta
    que la comprobación por backend de marca temporal estrictamente creciente
    (consulte <directive>ProxyBeaconSecret</directive>) bloquea las
    repeticiones independientemente de esta ventana. Esta directiva se usa en
    el proxy.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
