<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.en.xsl"?>
<!-- English Revision: 1.5.2.9  -->

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

<manualpage metafile="name-based.xml.meta">
<parentdocument href="./">Hosting Virtual</parentdocument>
<title>Soporte de Hosting Virtual basado en nombres</title>

<summary>
    <p>Este documento describe c&#243;mo y cu&#225;ndo debe usarse hosting virtual
    basado en nombres.</p>
</summary>

<seealso><a href="ip-based.html">Hosting virtual basado en
IPs</a></seealso>
<seealso><a href="details.html">Discusi&#243;n en profundidad sobre el
proceso de selecci&#243;n de host virtual</a></seealso>
<seealso><a href="mass.html">Configuraci&#243;n din&#225;mica de Hosting virtual masivo</a></seealso>
<seealso><a href="examples.html">Ejemplos de hosting virtual para
configuraciones t&#237;picas</a></seealso>
<seealso><a href="examples.html#serverpath">Ejemplo de 
configuraci&#243;n de ServerPath</a></seealso>

<section id="namevip"><title>Diferencias entre el hosting vitual
basado en nombres y el basado en IPs</title>

    <p>El hosting virtual basado en IPs usa la direcci&#243;n IP de la
    conexi&#243;n para determinar qu&#233; host virtual es el que tiene que
    servir.  Por lo tanto, necesitar&#225; tener diferentes direcciones IP
    para cada host. Si usa hosting virtual basado en nombres, el
    servidor atiende al nombre de host que especifica el cliente en
    las cabeceras de HTTP. Usando esta t&#233;cnica, una sola direcci&#243;n IP
    puede ser compartida por muchos sitios web diferentes.</p>

    <p>El hosting virtual basado en nombres es normalmente m&#225;s
    sencillo, porque solo necesita configurar su servidor de DNS para
    que localice la direcci&#243;n IP correcta y entonces configurar Apache
    para que reconozca los diferentes nombres de host. Usando hosting
    virtual basado en nombres tambi&#233;n se reduce la demanda de
    direcciones IP, que empieza a ser un bien escaso.  Por lo tanto,
    debe usar hosting virtual basado en nombres a no ser que haya
    alguna raz&#243;n especial por la cual tenga que elegir usar hosting
    vitual basado en direcciones IP. Algunas de &#233;stas razones pueden
    ser:</p>

    <ul>
        <li>Algunos clientes antiguos no son compatibles con el
        hosting virtual basado en nombres.  Para que el hosting
        virtual basado en nombres funcione, el cliente debe enviar la
        cabecera de Host HTTP. Esto es necesario para HTTP/1.1, y est&#225;
        implementado como extensi&#243;n en casi todos los navegadores
        actuales. Si necesita dar soporte a clientes obsoletos y usar
        hosting virtual basado en nombres, al final de este documento
        se describe una t&#233;cnica para que pueda hacerlo.</li>

        <li>El hosting virtual basado en nombres no se puede usar
        junto con SSL por la naturaleza del protocolo SSL.</li>

        <li>Algunos sistemas operativos y algunos elementos de red
        tienen implementadas t&#233;cnicas de gesti&#243;n de ancho de banda que
        no pueden diferenciar entre hosts a no ser que no est&#233;n en
        diferentes direcciones IP.</li>
    </ul>

</section>

<section id="using"><title>C&#243;mo usar hosting vitual basado en
nombres</title>

<related>
    <modulelist>
    <module>core</module>
    </modulelist>

    <directivelist>
	<directive module="core">DocumentRoot</directive>
	<directive module="core">NameVirtualHost</directive>
	<directive module="core">ServerAlias</directive>
	<directive module="core">ServerName</directive>
	<directive module="core">ServerPath</directive>
	<directive module="core" type="section">VirtualHost</directive>
    </directivelist>
</related>

    <p>Para usar hosting virtual basado en nombres, debe especificar
    en el servidor qu&#233; direcci&#243;n IP (y posiblemente qu&#233; puerto) se va
    a usar para atender las peticiones a los diferentes hosts.  Esto
    se hace con la directiva <directive
    module="core">NameVirtualHost</directive>. Normalmente, cualquiera
    o todas las direcciones IP del servidor pueden usarse, tambi&#233;n
    puede usar <code>*</code> como argumento para la directiva
    <directive module="core">NameVirtualHost</directive>. Si va a usar
    m&#225;s de un puerto (por ejemplo si va usar SSL) debe a&#241;adir un
    puerto a cada argumento, por ejemplo <code>*:80</code>. Tenga en
    cuenta que especificando una direcci&#243;n IP en la directiva
    <directive module="core">NameVirtualHost</directive> no hace que
    el servidor escuche autom&#225;ticamente en esa direcci&#243;n IP. Consulte
    la secci&#243;n <a href="../bind.html">Especificar las direcciones y
    puertos que usa Apache</a> para obtener m&#225;s informaci&#243;n. Adem&#225;s,
    cualquier direcci&#243;n IP especificada debe asociarse con un
    dispositivo de red del servidor.</p>

    <p>El siguiente paso es crear un bloque <directive type="section"
    module="core">VirtualHost</directive> para cada host diferente que
    quiera alojar en el servidor. El argumento de la directiva
    <directive type="section" module="core">VirtualHost</directive>
    debe ser el mismo que el argumento de la directiva <directive
    module="core">NameVirtualHost</directive> (por ejemplo, una
    direcci&#243;n IP, o un <code>*</code> para usar todas las direcciones
    que tenga el servidor).  Dentro de cada bloque <directive
    type="section" module="core">VirtualHost</directive>, necesitar&#225;
    como m&#237;nimo una directiva <directive
    module="core">ServerName</directive> para designar qu&#233; host se
    sirve y una directiva <directive
    module="core">DocumentRoot</directive> para indicar d&#243;nde est&#225;n
    los contenidos a servir dentro del sistema de ficheros.</p>

    <note><title>A&#241;adir hosts vituales a un servidor web ya existente</title>     
        <p>Si est&#225; a&#241;adiendo hosts virtuales a un servidor web ya
        existente, debe crear tambi&#233;n un bloque <directive
        type="section" module="core" >VirtualHost</directive> para el
        host que ya tenga funcionando. Los valores de las directivas
        <directive module="core">ServerName</directive> y <directive
        module="core" >DocumentRoot</directive> desde este nuevo host
        virtual deben tener los mismos valores que los de las
        directivas <directive module="core">ServerName</directive>
        <directive module="core">DocumentRoot</directive>
        globales. Ponga este host virtual como el primero en el
        archivo de configuraci&#243;n para que sea el que act&#250;e como host
        por defecto.</p>
    </note>

    <p>Por ejemplo, suponga que est&#225; sirviendo el dominio
    <code>www.domain.tld</code> y quiere a&#241;adir el host virtual
    <code>www.otherdomain.tld</code>, que apunta a la misma direcci&#243;n
    IP. Entonces, lo &#250;nico que tiene que hacer es a&#241;adir lo siguiente
    al fichero <code>httpd.conf</code>:</p>

    <example>
        NameVirtualHost *:80<br />
        <br />
        &lt;VirtualHost *:80&gt;<br />
        <indent>
            ServerName www.domain.tld<br />
            ServerAlias domain.tld *.domain.tld<br />
            DocumentRoot /www/domain<br />
        </indent>
        &lt;/VirtualHost&gt;<br />
        <br />
        &lt;VirtualHost *:80&gt;<br />
        <indent>ServerName www.otherdomain.tld<br />
            DocumentRoot /www/otherdomain<br />
        </indent>
        &lt;/VirtualHost&gt;<br />
    </example>

    <p>Tambi&#233;n puede optar por especificar una direcci&#243;n IP
    expl&#237;citamente en lugar de usar un <code>*</code> en las
    directivas <directive module="core" >NameVirtualHost</directive> y
    <directive type="section" module="core"
    >VirtualHost</directive>. Por ejemplo, puede hacer esto
    para hacer funcionar diferentes hosts virtuales basados en nombres
    en una direcci&#243;n IP, o basados en IPs, o un conjunto de hosts
    virtuales basados en nombres en otra direcci&#243;n.</p>

    <p>Tambi&#233;n puede que quiera que se acceda a un determinado sitio
    web usando diferentes nombres. Esto es posible con la directiva
    <directive module="core">ServerAlias</directive>, puesta dentro de
    la secci&#243;n <directive type="section" module="core"
    >VirtualHost</directive>. Por ejemplo, en el primer bloque
    <directive type="section" module="core">VirtualHost</directive> de
    arriba, la directiva <directive
    module="core">ServerAlias</directive> indica la lista de nombres
    que pueden usarse para acceder a un mismo sitio web:</p>

    <example>
        ServerAlias domain.tld *.domain.tld
    </example>

    <p>entonces las peticiones para todos los hosts en el dominio
    <code>domain.tld</code> ser&#225;n servidas por el host virtual
    <code>www.domain.tld</code>. Los car&#225;cteres comodines
    <code>*</code> y <code>?</code> pueden usarse para encontrar
    equivalencias con los nombres.  Por supuesto, no puede inventarse
    nombres y ponerlos en la directiva <directive
    module="core">ServerName</directive> o
    <code>ServerAlias</code>. Primero debe tener su servidor de DNS
    debidamente configurado para que pueda hacer corresponder esos
    nombres con una direcci&#243;n IP de su servidor.</p>

    <p>Para terminar, puede mejorar el rendimiento de la configuraci&#243;n
    de los hosts virtuales poniendo otras directivas dentro de las
    secciones <directive type="section"
    module="core">VirtualHost</directive>. La mayor parte de las
    directivas pueden ponerse en esos containers y cambiar&#225;n solo la
    configuraci&#243;n del host virtual al que se refieran. Para ver si una
    directiva en particualar puede usarse as&#237;, consulte el <a
    href="../mod/directive-dict.html#Context">Contexto</a> de la
    directiva. Las directivas de configuraci&#243;n especificadas en el
    <em>contexto del servidor principal</em> (fuera de
    cualquier secci&#243;n <directive type="section"
    module="core">VirtualHost</directive>) se usan &#250;nica y
    exclusivamente si sus valores no son sustituidos por alguno de los
    par&#225;metros de configuraci&#243;n del host virtual.</p>

    <p>Cuando llega una petici&#243;n, el servidor primero verifica si se
    est&#225; usando una direcci&#243;n IP que coincide con el valor de la
    directiva <directive module="core"
    >NameVirtualHost</directive>. Si es el caso, mirar&#225; en cada
    secci&#243;n <directive type="section"
    module="core">VirtualHost</directive> cuya IP coincida e intentar&#225;
    encontrar si el valor de la directiva <directive module="core"
    >ServerName</directive> o de la directiva <code>ServerAlias</code>
    coincide con el nombre del sitio web de la petici&#243;n. Si encuentra
    una coincidencia, usa la configuraci&#243;n de ese servidor. Si no la
    encuentra, usa <strong>el primer host virtual de la lista</strong>
    cuya direcci&#243;n IP coincida con el de la petici&#243;n.</p>

    <p>Como consecuencia, el primer host virtual de la lista es el que
    se usa <em>por defecto</em>.  La directiva <directive
    module="core">DocumentRoot</directive> del <em>servidor
    principal</em> no se usar&#225; <strong>nunca</strong> cuando una
    direcci&#243;n IP coincida con el valor de la directiva <directive
    module="core">NameVirtualHost</directive>. Si quiere usar una
    configuraci&#243;n especial para peticiones que no coinciden con ning&#250;n
    host virtual en concreto, ponga esa configuraci&#243;n en una secci&#243;n
    <directive type="section" module="core">VirtualHost</directive> y
    p&#243;ngala la primera en el fichero de configuraci&#243;n.</p>

</section>

<section id="compat"><title>Compatibilidad con navegadores
antiguos</title>

    <p>Como se dijo antes, hay algunos clientes que no env&#237;an los
    datos necesarios para que funcione correctamente el hosting
    virtual basado en nombres. Estos clientes van a recibir siempre
    como respuesta a sus peticiones, p&#225;ginas del primer host virtual
    que haya en la lista para esa direcci&#243;n IP (el host virtual
    <cite>primario</cite> basado en nombres).</p>

    <note><title>&#191;C&#243;mo de antiguo?</title> 
    <p>Tenga en cuenta que cuando decimos antiguo, queremos decir
    realmente antiguo. Es muy poco probable que encuentre uno de esos
    navegadores en uso todav&#237;a. Todas las versiones actuales de
    cualquier navegador env&#237;an la cabecera <code>Host</code> que se
    necesita para que el hosting virtual basado en nombres
    funcione.</p>
    </note>

    <p>Existe una manera de evitar este problema con la directiva
    <directive module="core">ServerPath</directive>, aunque es un poco
    complicada:</p>

    <p>Ejemplo de configuraci&#243;n:</p>

    <example>
        NameVirtualHost 111.22.33.44<br />
        <br />
        &lt;VirtualHost 111.22.33.44&gt;<br />
        <indent>
            ServerName www.domain.tld<br />
            ServerPath /domain<br />
            DocumentRoot /web/domain<br />
        </indent>
        &lt;/VirtualHost&gt;<br />
    </example>

    <p>&#191;Qu&#233; significa esto? Esto significa que una petici&#243;n de
    cualquier URI que empiece por "<code>/domain</code>" ser&#225; servida
    por el host virtual <code>www.domain.tld</code>. Esto significa
    que las p&#225;ginas pueden accederse como
    <code>http://www.domain.tld/domain/</code> por todos los clientes,
    aunque los clientes que env&#237;en una cabecera <code>Host:</code>
    pueden tambi&#233;n acceder con
    <code>http://www.domain.tld/</code>.</p>

    <p>Para hacer que esto funcione, ponga un enlace en la p&#225;gina de
    su host virtual primario a
    <code>http://www.domain.tld/domain/</code>. Entonces, en las
    p&#225;ginas del host virtual, aseg&#250;rese de que usa o enlaces relativos
    (<em>por ejemplo</em>, "<code>file.html</code>" o
    "<code>../icons/image.gif</code>") o enlaces que contengan el
    <code>/domain/</code> anterior (<em>por ejemplo</em>,
    "<code>http://www.domain.tld/domain/misc/file.html</code>" o
    "<code>/domain/misc/file.html</code>").</p>

    <p>Esto requiere un poco de disciplina, pero siguiendo estas
    reglas, puede asegurarse, casi en todos los casos, de que las
    p&#225;ginas de su sitio web podr&#225;n ser accedidas desde cualquier
    navegador, ya sea nuevo o antiguo.</p>

</section>
</manualpage>



