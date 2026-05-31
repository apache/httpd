<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Glosario - Servidor HTTP Apache Versi&oacute;n 2.4</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet">
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size">
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css"><link rel="stylesheet" type="text/css" href="./style/css/prettify.css">
<script src="./style/scripts/prettify.min.js">
</script>

<link href="./images/favicon.png" rel="shortcut icon"></head>
<body id="manual-page" class="no-sidebar"><div id="page-header">
<p class="menu"><a href="./mod/">M&oacute;dulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p>
<p class="apache">Versi&oacute;n 2.4 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.png"></div>
<div class="up"><a href="./"><img title="<-" alt="<-" src="./images/left.gif"></a></div>
<div id="path">
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="./">Versi&oacute;n 2.4</a></div><div id="page-content"><div id="preamble"><h1>Glosario</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/glossary.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/glossary.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/glossary.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/glossary.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/glossary.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/glossary.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/glossary.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>

	<p>&Eacute;ste glosario define las terminolog&iacute;as m&aacute;s comunes
	relacionada con Apache en particular, y con los servidores web en
	general. En los enlaces que hay asociados a cada t&eacute;rmino se puede
	encontrar informaci&oacute;n m&aacute;s detallada de cada uno.</p>
	</div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section">
<h2 id="definitions">Definiciones <a title="Enlace permanente" href="#definitions" class="permalink">&para;</a></h2>
		<dl>
		<dt><a name="algorithm" id="algorithm">Algoritmo</a></dt>
		<dd>Un proceso definido sin ambig&uuml;edades o un conjunto de reglas 
		para solucionar un problema en un n&uacute;mero finito de pasos.
		Los algoritmos para encriptar se llaman
		normalmente <dfn>algoritmos de cifrado</dfn>.
		</dd>


		<dt><a name="cipher" id="cipher">Algoritmo de cifrado, (Cipher). </a></dt>
		<dd>Es un algoritmo o sistema de encriptado de informaci&oacute;n. 
		Ejemplos de estos algoritmos son DES, IDEA, RC4, etc.<br>
		Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>

		<dt><a name="authentication" id="authentication">Autenticaci&oacute;n.</a></dt>
		<dd>La identificaci&oacute;n positiva de una entidad de red tal como un
		servidor, un cliente, o un usuario.<br> 
		Consulte: <a href="howto/auth.html">Autentificaci&oacute;n, Autorizaci&oacute;n, 
		y Control de Acceso</a></dd>


		<dt><a name="certificationauthority" id="certificationauthority">Autoridad Certificadora.</a> <a name="ca">(CA)</a></dt> <dd>Es una entidad externa de confianza cuyo fin
		es firmar certificados para las entidades de red que ha autentificado
		usando medios seguros. Otras entidades de red pueden verificar la
		firma para comprobar que una Autoridad Certificadora ha autentificado
		al poseedor del certificado.<br> Consulte: <a href="ssl/">Encriptado
		SSL/TLS</a></dd>


		<dt><a name="header" id="header">Cabecera.</a></dt> <dd>Es la parte de la
		petici&oacute;n y la respuesta <a class="glossarylink" href="./glossary.html#http" title="ver glosario">HTTP</a> que se
		env&iacute;a antes del contenido propiamente dicho, y que contiene
		meta-informaci&oacute;n describiendo el contenido.</dd>

		<dt><a name="certificate" id="certificate">Certificado.</a></dt>
		<dd>Una informaci&oacute;n que se almacena para autenticar entidades
		de red tales como un servidor o un cliente. Un certificado
		contiene piezas de informaci&oacute;n X.509 sobre su poseedor
		(llamado sujeto) y sobre la <a class="glossarylink" href="./glossary.html#certificationauthority" title="ver glosario">Autoridad Certificadora</a>
		(llamada el emisor) que lo firma, m&aacute;s la <a class="glossarylink" href="./glossary.html#publickey" title="ver glosario">clave p&uacute;blica</a> del propietario y la firma de
		la AC(Autoridad Certificadora). Las entidades de red verifican las firmas usando
		certificados de las AC.<br>
		Consulte: <a href="ssl/">Encriptado SSL/TLS</a>
		</dd>



		<dt><a name="publickey" id="publickey">Clave P&uacute;blica.</a></dt> 
		<dd>La clave disponible
		p&uacute;blicamente en un <a class="glossarylink" href="./glossary.html#publickeycryptography" title="ver glosario">sistema
		criptogr&aacute;fico de Clave P&uacute;blica</a>, usado para encriptar
		mensajes destinados a su propietario y para desencriptar firmas hechas
		por su propietario.<br> Consulte: <a href="ssl/">Encriptado
		SSL/TLS</a></dd>



		<dt><a name="privatekey" id="privatekey">Clave Privada.</a></dt>
		<dd>La clave secreta
		de un <a class="glossarylink" href="./glossary.html#publickeycryptography" title="ver glosario">Sistema criptogr&aacute;fico de
		Clave P&uacute;blica</a>, usada para desencriptar los mensajes entrantes
		y firmar los salientes.<br> Consulte: <a href="ssl/">Encriptado
		SSL/TLS</a></dd>


		<dt><a name="connect" id="connect">CONNECT</a></dt> <dd>Un <a class="glossarylink" href="./glossary.html#method" title="ver glosario">m&eacute;todo</a> de HTTP para hacer proxy a canales de
		datos sin usar HTTP. Puede usarse para encapsular otros protocolos,
		tales como el protocolo SSL.</dd>



		<dt><a name="context" id="context">Contexto</a></dt> <dd>Un &aacute;rea en los
		<a class="glossarylink" href="./glossary.html#configurationfile" title="ver glosario">ficheros de configuraci&oacute;n</a>
		donde est&aacute;n permitidos ciertos tipos de <a class="glossarylink" href="./glossary.html#directive" title="ver glosario">directivas</a>.<br>
		Consulte: <a href="mod/directive-dict.html#Context">T&eacute;rminos 
		usados para describir las directivas de Apache</a></dd>


		<dt><a name="accesscontrol" id="accesscontrol">Control de Acceso.</a></dt> 
		<dd>La
		restricci&oacute;n en el acceso al entorno de una red. En el contexto de
		Apache significa normalmente la restricci&oacute;n en el acceso a
		ciertas <em>URLs</em>.<br> 
		Consulte: <a href="howto/auth.html">Autentificaci&oacute;n, Autorizaci&oacute;n, y
		Control de Acceso</a></dd>


		<dt><a name="symmetriccryptophraphy">Criptograf&iacute;a
		Sim&eacute;trica</a></dt> <dd>El estudio y aplicaci&oacute;n de
		<em>Algoritmos de Cifrado</em> que usan una sola clave secreta tanto
		para cifrar como para descifrar.<br> Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>


		<dt><a name="directive" id="directive">Directiva</a></dt>
		<dd>Un comando de
		configuraci&oacute;n que controla uno o m&aacute;s aspectos del
		comportamiento de Apache.  Las directivas se ponen en el <a class="glossarylink" href="./glossary.html#configurationfile" title="ver glosario">Fichero de Configuraci&oacute;n</a><br>
		Consulte: <a href="mod/directives.html">&Iacute;ndice de
		Directivas</a></dd>

		<dt><a name="configurationdirective" id="configurationdirective">Directivas de
		configuraci&oacute;n.</a></dt> <dd>Consulte: <a class="glossarylink" href="./glossary.html#directive" title="ver glosario">Directivas</a></dd>

		<dt><a name="apacheportableruntime" id="apacheportableruntime">Entorno Portable de tiempo de ejecuci&oacute;n de Apache, </a> <a name="apr" id="apr">(APR, Apache Portable Runtime)</a></dt>
		<dd>Es un conjunto de librer&iacute;as que proveen las interfaces b&aacute;sicas 
		entre el servidor y el sistema operativo. El desarrollo de APR es 
		paralelo al del Servidor HTTP Apache, como un proyecto independiente. 
		Puedes visitar el proyecto en:<br>
		<a href="http://apr.apache.org/">Apache Portable Runtime
		Project</a>
		</dd>

		<dt><a name="export-crippled" id="export-crippled">Export-Crippled</a></dt>
		<dd>Disminuci&oacute;n de la fortaleza criptogr&aacute;fica (y seguridad)
		para cumplir con las Regulaciones sobre Exportaci&oacute;n de la
		Administraci&oacute;n de los Estados Unidos (EAR). El software
		criptogr&aacute;fico Export-crippled est&aacute; limitado a una clave de
		peque&ntilde;o tama&ntilde;o, de tal manera que el <em>texto cifrado</em>
		que se consigue con &eacute;l, puede descifrarse por medio de fuerza bruta.<br> Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>


		<dt><a name="regularexpresion" id="regularexpresion">Expresiones Regulares</a> 
		<a name="regex">(Regex)</a></dt> <dd>Una forma de describir un patr&oacute;n en un 
		texto - por ejemplo, "todas las palabras que empiezan con la letra "A"
		o "todos los n&uacute;meros de tel&eacute;fono que contienen 10
		d&iacute;gitos" o incluso "Todas las frases entre comas, y que no
		contengan ninguna letra Q". Las Expresiones Regulares son &uacute;tiles en
		Apache porque permiten aplicar ciertos atributos a colecciones de
		ficheros o recursos de una forma flexible - por ejemplo, todos los
		archivos .gif y .jpg que est&eacute;n en el directorio "im&aacute;genes"
		podr&iacute;an ser escritos como "<code>/images/.*(jpg|gif)$</code>".
		En los lugares donde expresiones regulares se utilizan para reemplazar
		cadenas, las variables especiales $ 1 ... $ 9 contienen 
		referencias inversa las partes agrupadas (entre par&eacute;ntesis) 
		de la expresi&oacute;n coincidente. La variable especial $ 0 contiene 
		una referencia inversa a todo el ejemplar de la expresi&oacute;n.
		Para escribir un s&iacute;mbolo de dolar literal en una sustituci&oacute;n de
		una cadena, se puede escapar usando "\". Hist&oacute;ricamente, la variable &amp;
		se pod&iacute;a usar como un alias a $0 en algunos sitios. 
		Esto ya no esta soportado desde la versi&oacute;n 2.3.6.
		Apache usa Expresiones Regulares compatibles con Perl gracias a la
		librer&iacute;a <a href="http://www.pcre.org/">PCRE</a>.
		Puedes encontrar m&aacute;s documentaci&oacute;n sobre las expresiones regulares 
		de PCRE y su sintaxis en esa p&aacute;gina o en la
		<a href="http://en.wikipedia.org/wiki/PCRE">Wikipedia</a>.</dd>



		<dt><a name="configurationfile" id="configurationfile">Fichero de Configuraci&oacute;n.</a></dt>
		<dd>Un fichero de texto que contiene <a class="glossarylink" href="./glossary.html#directive" title="ver glosario">Directivas</a> que controlan la configuraci&oacute;n
		de Apache.<br> Consulte: <a href="configuring.html">Ficheros de
		Configuraci&oacute;n</a></dd>


		<dt><a name="htaccess" id="htaccess">.htaccess</a></dt> 
		<dd>Un <a class="glossarylink" href="./glossary.html#configurationfile" title="ver glosario">fichero de configuraci&oacute;n</a> que se
		pone dentro de la estructura de directorios del sitio web y aplica <a class="glossarylink" href="./glossary.html#directive" title="ver glosario">directivas</a> de configuraci&oacute;n al directorio
		en el que est&aacute; y a sus subdirectorios. A pesar de su nombre, este
		fichero puede contener cualquier tipo de directivas, no solo
		directivas de control de acceso.<br> Consulte: <a href="configuring.html">Ficheros de Configuraci&oacute;n</a> para m&aacute;s informaci&oacute;n.</dd>

		<dt><a name="httpd.conf" id="httpd.conf">httpd.conf</a></dt>
		<dd>Es el <a class="glossarylink" href="./glossary.html#configurationfile" title="ver glosario">fichero de configuraci&oacute;n</a> principal
		de Apache. Su ubicaci&oacute;n por defecto es
		<code>/usr/local/apache2/conf/httpd.conf</code>, pero puede moverse
		usando opciones de configuraci&oacute;n al compilar o al iniciar
		Apache.<br> Consulte: <a href="configuring.html">Ficheros de
		Configuraci&oacute;n</a></dd>

		<dt><a name="filter" id="filter">Filtro</a></dt>
		<dd>Un proceso que se aplica a la
		informaci&oacute;n que es enviada o recibida por el servidor. Los
		ficheros de entrada procesan la informaci&oacute;n enviada por un
		cliente al servidor, mientras que los filtros de salida procesan la
		informaci&oacute;n en el servidor antes de envi&aacute;rsela al
		cliente. Por ejemplo, el filtro de salida <code>INCLUDES</code>
		procesa documentos para <a class="glossarylink" href="./glossary.html#ssi" title="ver glosario">Server Side Includes</a>.<br>
		Consulte: <a href="filter.html">Filtros</a></dd>



		<dt><a name="digitalsignature" id="digitalsignature">Firma Digital</a></dt>
		<dd>Un bloque de
		texto encriptado que verifica la validez de un certificado o de otro
		fichero. Una <a class="glossarylink" href="./glossary.html#certificationauthority" title="ver glosario">Autoridad
		Certificadora</a> crea una firma generando un hash a partir de la
		<em>Clave P&uacute;blica</em> que lleva incorporada en un
		<em>Certificado</em>, despu&eacute;s encriptando el hash con su propia
		<em>Clave Privada</em>. Solo las claves p&uacute;blicas de las CAs
		pueden desencriptar la firma, verificando que la CA ha autentificado a
		la entidad de red propietaria del <em>Certificado</em>.<br>
		Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>

		<dt><a name="handler" id="handler">Handler</a></dt> 
		<dd>Es una representaci&oacute;n
		interna de Apache de una acci&oacute;n a ser ejecutada cuando se llama a
		un fichero. Generalmente, los ficheros tienen un handler (manejador)
		impl&iacute;cito, basado en el tipo de fichero. Normalmente, todos los
		ficheros son simplemente servidos por el servidor, pero sobre algunos
		tipos de ficheros se ejecutan acciones complementarias.  Por ejemplo,
		el handler <code>cgi-script</code> designa los ficheros a ser
		procesados como <a class="glossarylink" href="./glossary.html#cgi" title="ver glosario">CGIs</a>.<br> Consulte: <a href="handler.html">Uso de Handlers en Apache</a></dd>

		<dt><a name="apacheextensiontool" id="apacheextensiontool">Herramienta de extensi&oacute;n de
		Apache.</a> <a name="apxs" id="apxs">(apxs)</a></dt>
		<dd>Es un script escrito en Perl que ayuda a compilar el c&oacute;digo
		fuente de algunos <a class="glossarylink" href="./glossary.html#module" title="ver glosario">m&oacute;dulos</a> para 
		convertirlos en Objetos Din&aacute;micos Compartidos (<a class="glossarylink" href="./glossary.html#dso.html" title="ver glosario">DSO</a>s)
		y ayuda a instalarlos en el Servidor Web de Apache.<br> 
		Consulte: Manual de: <code class="program"><a href="./programs/apxs.html">apxs</a></code></dd>



		<dt><a name="hash" id="hash">Hash</a></dt>
		<dd>Algoritmo matem&aacute;tico de un solo sentido e irreversible, que genera
		una cadena de una determinada longitud de otra cadena de 
		cualquier tama&ntilde;o. Diferentes entradas dar&aacute;n diferentes hashes 
		(dependiendo de la funci&oacute;n hash.) 
		</dd>





		<dt><a name="virtualhosting">Hosting Virtual</a></dt> <dd>Se trata de
		servir diferentes sitios web con una sola entidad de Apache.  <em>El
		hosting virtual de IPs</em> diferencia los sitios web bas&aacute;ndose en sus
		direcciones IP, mientras que el <em>hosting virtual basado en
		nombres</em> usa solo el nombre del host y de esta manera puede alojar
		muchos sitios web con la misma direcci&oacute;n IP.<br> Consulte: <a href="vhosts/">Documentaci&oacute;n sobre Hosting Virtual en
		Apache</a></dd>


		<dt><a name="uniformresourceidentifier">Identificador de Recursos
		Uniforme</a> <a name="URI">(URI)</a></dt> <dd>Una cadena de caracteres
		compacta para identificar un recurso f&iacute;sico o abstracto.  Se
		define formalmente en la <a href="http://www.ietf.org/rfc/rfc2396.txt">RFC 2396</a>.  Los URIs que
		se usan en world-wide web se refieren normalmente como <a href="#url">URLs</a>.</dd>




		<dt><a name="servernameindication" id="servernameindication">Indicador del Nombre del servidor</a>
		<a name="sni" id="sni"> Server Name Indication (SNI) </a></dt>
		<dd>Una funci&oacute;n SSL que permite pasar el nombre de host del servidor deseado 
		en el mensaje inicial del protocolo de enlace SSL, para que el servidor web 
		pueda seleccionar la configuraci&oacute;n correcta del host virtual para usar en el 
		procesamiento del protocolo de enlace SSL. Se a&ntilde;adi&oacute; a SSL 
		con las extensiones TLS en el RFC 3546.  <br>
		See: <a href="ssl/ssl_faq.html">the SSL FAQ</a>
		and <a href="http://www.ietf.org/rfc/rfc3546.txt">RFC 3546</a>
		</dd>




		<dt><a name="commongatewayinterface" id="commongatewayinterface">Interfaz de Pasarela Com&uacute;n.</a> <a name="cgi"> Common Gateway Interface (CGI)</a></dt>
		<dd>Una definici&oacute;n est&aacute;ndar para
		un interfaz entre un servidor web y un programa externo que permite
		hacer peticiones de servicio a los programas externos.  Este interfaz
		esta definido en el  <a href="http://www.ietf.org/rfc/rfc3875">RFC-3875</a>.<br>
		Consulte: <a href="howto/cgi.html">Contenido Din&aacute;mico con CGI</a>
		</dd>

		<dt><a name="uniformresourcelocator">Localizador de Recursos
		Uniforme</a> <a name="url">(URL)</a></dt>
		<dd>El nombre de un recurso
		en Internet.  Es la manera informal de decir lo que formalmente se
		llama un <a href="#uniformresourceidentifier">Identificador de
		Recursos Uniforme</a>.  Las URLs est&aacute;n compuestas normalmente por
		un esquema, tal como <code>http</code> o <code>https</code>, un nombre
		de host, y una ruta.  Una URL para esta p&aacute;gina es
		<code>http://httpd.apache.org/docs/2.4/glossary.html</code>.</dd>


		<dt><a name="module" id="module">M&oacute;dulo</a></dt>
		<dd>Una parte independiente
		de un programa. La mayor parte de la funcionalidad de Apache
		est&aacute; contenida en m&oacute;dulos que pueden incluirse o excluirse.
		Los m&oacute;dulos que se compilan con el binario <code class="program"><a href="./programs/httpd.html">httpd</a></code>de Apache se
		llaman <em>m&oacute;dulos est&aacute;ticos</em>, mientras que los que se
		almacenan de forma separada y pueden ser cargados de forma opcional,
		se llaman <em>m&oacute;dulos din&aacute;micos</em> o <a class="glossarylink" href="./glossary.html#dso" title="ver glosario">DSOs</a>.
		Los m&oacute;dulos que est&aacute;n incluidos por defecto de llaman
		<em>m&oacute;dulos base</em>.  Hay muchos m&oacute;dulos disponibles para
		Apache que no se distribuyen con la <a class="glossarylink" href="./glossary.html#tarball" title="ver glosario">tarball</a> del
		Servidor HTTP Apache.  Estos m&oacute;dulos son llamados
		<em>m&oacute;dulos de terceros</em>.<br> Consulte: <a href="mod/">&Iacute;ndice de M&oacute;dulos</a></dd>


		<dt><a name="method" id="method">M&eacute;todo</a></dt> 
		<dd>En el contexto de <a class="glossarylink" href="./glossary.html#http" title="ver glosario">HTTP</a>, es una acci&oacute;n a ejecutar sobre un recurso,
		especificado en la l&iacute;neas de petici&oacute;n por el cliente.
		Algunos de los m&eacute;todos disponibles en HTTP son <code>GET</code>,
		<code>POST</code>, y <code>PUT</code>.</dd>

		<dt><a name="messagedigest" id="messagedigest">Mensaje Resumen (Message Digest)</a></dt> 
		<dd>Un hash de un
		mensaje, el cual pude ser usado para verificar que el contenido del
		mensaje no ha sido alterado durante la transmisi&oacute;n.<br>
		Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>

		<dt><a name="mime-type" id="mime-type">MIME-type</a></dt> 
		<dd>Una manera de describir
		el tipo de documento a ser transmitido.  Su nombre viene del hecho de
		que su formato se toma de las Extensiones del "Multipurpose Internet
		Mail".  Consiste en dos componentes, uno principal y otro secundario,
		separados por una barra.  Algunos ejemplos son <code>text/html</code>,
		<code>image/gif</code>, y <code>application/octet-stream</code>.  En
		HTTP, el tipo MIME se transmite en la <a class="glossarylink" href="./glossary.html#header" title="ver glosario">cabecera</a>
		del <code>Tipo Contenido</code>.<br> Consulte: <a href="mod/mod_mime.html">mod_mime</a></dd>

		<dt><a name="modulemagicnumber" id="modulemagicnumber">M&oacute;dulo del N&uacute;mero M&aacute;gico</a>
		(<a name="mmn">MMN Module Magic
		Number</a>)</dt> <dd> El m&oacute;dulo del n&uacute;mero
		m&aacute;gico es una constante definida en el c&oacute;digo
		fuente de Apache que est&aacute; asociado con la compatibilidad binaria
		de los m&oacute;dulos. Ese n&uacute;mero cambia cuando cambian las
		estructuras internas de Apache, las llamadas a funciones y otras
		partes significativas de la interfaz de programaci&oacute;n de manera
		que la compatibilidad binaria no puede garantizarse sin cambiarlo.  Si
		cambia el n&uacute;mero m&aacute;gico de m&oacute;dulo, todos los
		m&oacute;dulos de terceros tienen que ser al menos recompilados, y
		algunas veces, incluso hay que introducir ligeras modificaciones para
		que funcionen con la nueva versi&oacute;n de Apache </dd>


		<dt><a name="fully-qualifieddomain-name" id="fully-qualifieddomain-name">Nombre de dominio
		completamente qualificado</a> <a name="fqdn">(FQDN)</a></dt> 
		<dd>El
		nombre &uacute;nico de una entidad de red, que consiste en un nombre de
		host y un nombre de dominio que puede traducirse a una direcci&oacute;n
		IP. Por ejemplo, <code>www</code> es un nombre de host,
		<code>example.com</code> es un nombre de dominio, y
		<code>www.example.com</code> es un nombre de dominio completamente
		qualificado.</dd>

		<dt><a name="dynamicsharedobject" id="dynamicsharedobject">Objetos Din&aacute;micos
		Compartidos</a> <a name="dso">(DSO, dinamic shared objects)</a></dt>
		<dd>Los <a class="glossarylink" href="./glossary.html#module" title="ver glosario">M&oacute;dulos</a> compilados de forma separada al
		binario httpd de Apache se pueden cargar seg&uacute;n se necesiten.<br> Consulte: <a href="dso.html">Soporte de Objetos Din&aacute;micos
		Compartidos</a></dd>


		<dt><a name="openssl" id="openssl">OpenSSL</a></dt>
		<dd>El toolkit Open Source para SSL/TLS<br>
		Ver: <a href="http://www.openssl.org/">http://www.openssl.org/</a></dd>


		<dt><a name="passphrase">Pass Phrase o frase de contrase&ntilde;a</a></dt> 
		<dd>La palabra o frase
		que protege los archivos de clave privada.  Evita que usuarios no
		autorizados los encripten. Normalmente es solo la clave de
		encriptado/desencriptado usada por los <a class="glossarylink" href="./glossary.html#cipher" title="ver glosario">Algoritmos de
		Cifrado</a>.<br> Consulte: <a href="ssl/">Encriptado
		SSL/TLS</a></dd>

		<dt><a name="certificatsigningrequest" id="certificatsigningrequest">Petici&oacute;n de firma de
		Certificado.</a> <a name="csr">(CSR)</a></dt> 
		<dd>Es la petici&oacute;n a
		una <a class="glossarylink" href="./glossary.html#certificationauthority" title="ver glosario">Autoridad Certificadora</a> para
		que firme un <a class="glossarylink" href="./glossary.html#certificate" title="ver glosario">certificado</a> a&uacute;n sin
		firmar. La Autoridad Certificadora firma el <em>Certificado</em> con
		la <a class="glossarylink" href="./glossary.html#privatekey" title="ver glosario">Clave Privada</a> de su 
		<em>certificado</em>. Una vez que el CSR est&aacute; firmado, se 
		convierte en un aut&eacute;ntico certificado.<br> 
		Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>



		<dt><a name="hypertexttransferprotocol" id="hypertexttransferprotocol">Protocolo de Transferencia de
		Hipertexto</a> <a name="http">(HTTP)</a></dt> 
		<dd>Es el protocolo de
		transmisi&oacute;n est&aacute;dar usado en la World Wide Web.  Apache
		implementa la versi&oacute;n 1.1 de este protocolo, al que se hace
		referencia como HTTP/1.1 y definido por el <a href="http://ietf.org/rfc/rfc2616.txt">RFC 2616</a>.</dd>

		<dt><a name="https" id="https">HTTPS</a></dt>
		<dd>Protocolo de transferencia de
		Hipertexto (Seguro), es el mecanismo de comunicaci&oacute;n encriptado
		est&aacute;ndar en World Wide Web. En realidad es HTTP sobre <a class="glossarylink" href="./glossary.html#ssl" title="ver glosario">SSL</a>.<br> Consulte: <a href="ssl/">Encriptado
		SSL/TLS</a></dd>

		<dt><a name="proxy" id="proxy">Proxy</a></dt> <dd>Un servidor intermedio que se
		pone entre el cliente y el <em>servidor de origen</em>.  Acepta las
		peticiones de los clientes, las transmite al servidor de origen, y
		despu&eacute;s devuelve la respuesta del servidor de origen al
		cliente. Si varios clientes piden el mismo contenido, el proxy sirve
		el contenido desde su cach&eacute;, en lugar de pedirlo cada vez que lo
		necesita al servidor de origen, reduciendo con esto el tiempo de
		respuesta.<br> Consulte: <a href="mod/mod_proxy.html">mod_proxy</a></dd>


		<dt><a name="reverseproxy" id="reverseproxy">Proxy Inverso</a></dt>
		<dd>Es un servidor
		<a href="proxy">proxy</a> que se presenta al cliente como si fuera un
		<em>servidor de origen</em>.  Es &uacute;til para esconder el
		aut&eacute;ntico servidor de origen a los clientes por cuestiones de
		seguridad, o para equilibrar la carga.</dd>


		<dt><a name="securesocketslayer" id="securesocketslayer">SSL, Capa de Conexi&oacute;n Segura </a> <a name="ssl">Secure Sockets Layer(SSL)</a></dt> <dd>Es un protocolo creado por Netscape
		Communications Corporation para la autenticaci&oacute;n en
		comunicaciones en general y encriptado sobre redes TCP/IP. Su
		aplicaci&oacute;n m&aacute;s popular es en <em>HTTPS</em>, ejemplo.: el Protocolo de
		Transferencia de Hipertexto (HTTP) sobre SSL.<br> Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>


		<dt><a name="ssleay" id="ssleay">SSLeay</a></dt> <dd>La implementaci&oacute;n
		original de la librer&iacute;a SSL/TLS desarrollada por Eric
		A. Young</dd>



		<dt><a name="serversideincludes" id="serversideincludes">Server Side Includes</a> <a name="ssi">(SSI)</a></dt> <dd>Una t&eacute;cnica para incluir directivas de
		proceso en archivos HTML.<br> Consulte: <a href="howto/ssi.html">Introducci&oacute;n a Server Side
		Includes</a></dd>



		<dt><a name="session" id="session">Sesi&oacute;n</a></dt> <dd>Informaci&oacute;n del
		contexto de una comunicaci&oacute;n en general.</dd>


		<dt><a name="publickeycryptography" id="publickeycryptography">Sistema Criptogr&aacute;fico de Clave
		P&uacute;blica</a></dt> <dd>El estudio y aplicaci&oacute;n de sistemas de
		encriptado asim&eacute;tricos, que usa una clave para encriptar y otra
		para desencriptar. Una clave de cada uno de estos tipos constituye un
		par de claves. Tambi&eacute;n se llama Criptograf&iacute;a Asim&eacute;trica.<br>
		Consulte: <a href="ssl/"> Encriptado SSL/TLS</a></dd>


		<dt><a name="subrequest" id="subrequest">Subconsulta</a></dt>
		<dd>Apache proporciona una API de subconsultasd a los m&oacute;dulos,
		que permiten a otros sistemas de ficheros o paths de URL ser parcial o totalmente evaluados
		por el servidor. Un ejemplo de los que usan esta API ser&iacute;a
		<code class="directive"><a href="./mod/mod_dir.html#directoryindex">DirectoryIndex</a></code>,
		<code class="module"><a href="./mod/mod_autoindex.html">mod_autoindex</a></code>, y <code class="module"><a href="./mod/mod_include.html">mod_include</a></code>.
		</dd>

		<dt><a name="tarball" id="tarball">Tarball</a></dt> <dd>Un grupo de ficheros
		puestos en un solo paquete usando la utilidad <code>tar</code>.  Las
		distribuciones Apache se almacenan en ficheros comprimidos con tar o
		con pkzip.</dd>

		<dt><a name="ciphertext" id="ciphertext">Texto cifrado.</a></dt> 
		<dd>El resultado de
		haber aplicado a un <a class="glossarylink" href="./glossary.html#plaintext" title="ver glosario">texto plano</a> un <a class="glossarylink" href="./glossary.html#cipher" title="ver glosario">algoritmo de cifrado</a>.<br> Consultar: <a href="ssl/">Encriptado SSL/TLS</a></dd>



		<dt><a name="plaintext" id="plaintext">Texto plano</a></dt>
		<dd>Un texto no encriptado.</dd>


		<dt><a name="transportlayersecurity" id="transportlayersecurity">Transport 
			Layer Security</a> <a name="tls">(TLS)</a></dt> <dd>Es el sucesor del protocolo SSL, creado
		por el "Internet Engineering Task Force" (IETF) para la
		autentificaci&oacute;n en comunicaciones en general y encriptado sobre
		redes TCP/IP. La versi&oacute;n 1 de TLS es casi id&eacute;ntica a la
		versi&oacute;n 3 de SSL.<br> Consulte: <a href="ssl/">Encriptado
		SSL/TLS</a></dd>


		<dt><a name="environmentvariable" id="environmentvariable">Variable de Entorno</a> <a name="env-variable">(env-variable)</a></dt> 
		<dd>Variables que
		gestionan el shell del sistema operativo y que se usan para guardar
		informaci&oacute;n y para la comunicaci&oacute;n entre programas.  Apache
		tambi&eacute;n contiene variables internas que son referidas como
		variables de entorno, pero que son almacenadas en las estructuras
		internas de Apache, en lugar de en el entorno del shell.<br>
		Consulte: <a href="env.html">Variables de entorno de Apache</a></dd>


		<dt><a name="x.509" id="x.509">X.509</a></dt> <dd>Un esquema de certificado de
		autentificaci&oacute;n recomendado por la International
		Telecommunication Union (ITU-T) que se usa en la autentificaci&oacute;n
		SSL/TLS.<br> Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>

		</dl>
	</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/glossary.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/glossary.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/glossary.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/glossary.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/glossary.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/glossary.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/glossary.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a></p>
</div><div id="footer">
<p class="apache">Copyright 2026 The Apache Software Foundation.<br>Licencia bajo los t&eacute;rminos de la <a href="https://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="./mod/">M&oacute;dulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p></div><script><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
var langToggle = document.querySelector('.lang-toggle');
var topLang = document.querySelector('.toplang');
if (langToggle && topLang) {
    langToggle.addEventListener('click', function() { topLang.classList.toggle('open'); });
}
var qv = document.getElementById('quickview');
if (qv) {
    document.body.appendChild(qv);
    var qvBtn = document.createElement('button');
    qvBtn.className = 'qv-toggle';
    qvBtn.setAttribute('aria-label', 'Toggle page navigation');
    qvBtn.innerHTML = '&#9776;';
    document.body.appendChild(qvBtn);
    qvBtn.addEventListener('click', function() {
        var isOpen = qv.classList.toggle('open');
        if (isOpen) {
            qv.style.top = window.scrollY + 10 + 'px';
        }
    });
    window.addEventListener('scroll', function() { qv.classList.remove('open'); });
}
//--><!]]></script>
</body></html>