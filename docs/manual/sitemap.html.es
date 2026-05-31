<!DOCTYPE html SYSTEM "about:legacy-compat">
<html lang="es"><head><META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<meta content="width=device-width, initial-scale=1" name="viewport">
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Mapa de este sitio web - Servidor HTTP Apache Versi&oacute;n 2.4</title>
<link href="./style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet">
<link href="./style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size">
<link href="./style/css/manual-print.css" rel="stylesheet" media="print" type="text/css"><link rel="stylesheet" type="text/css" href="./style/css/prettify.css">
<script src="./style/scripts/prettify.min.js">
</script>

<link href="./images/favicon.png" rel="shortcut icon"></head>
<body id="manual-page">
<div id="page-header">
<p class="menu"><a href="./mod/">M&oacute;dulos</a> | <a href="./mod/quickreference.html">Directivas</a> | <a href="https://cwiki.apache.org/confluence/display/httpd/FAQ">Preguntas Frecuentes</a> | <a href="./glossary.html">Glosario</a> | <a href="./sitemap.html">Mapa del sitio web</a> | <a href="https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2">Reportar un error</a></p>
<p class="apache">Versi&oacute;n 2.4 del Servidor HTTP Apache</p>
<img alt="" src="./images/feather.png"></div>
<div class="up"><a href="./"><img title="<-" alt="<-" src="./images/left.gif"></a></div>
<div id="path">
<a href="https://www.apache.org/">Apache</a> &gt; <a href="https://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="https://httpd.apache.org/docs/">Documentaci&oacute;n</a> &gt; <a href="./">Versi&oacute;n 2.4</a></div>
<div id="page-content"><div id="preamble"><h1>Mapa de este sitio web</h1>
<button aria-label="Toggle language list" class="lang-toggle"><svg xmlns="http://www.w3.org/2000/svg" stroke-width="2" stroke="currentColor" fill="none" viewBox="0 0 24 24" height="16" width="16"><circle r="10" cy="12" cx="12"/><line y2="12" x2="22" y1="12" x1="2"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></button>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="./de/sitemap.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/sitemap.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/sitemap.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/sitemap.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/sitemap.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/sitemap.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/sitemap.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a> |
<a href="./zh-cn/sitemap.html" hreflang="zh-cn" rel="alternate" title="Simplified Chinese">&nbsp;zh-cn&nbsp;</a></p>
</div>
<div class="outofdate">Esta traducci&oacute;n podr&iacute;a estar
            obsoleta. Consulte la versi&oacute;n en ingl&eacute;s de la
            documentaci&oacute;n para comprobar si se han producido cambios
            recientemente.</div>

<p>Esta p&aacute;gina contiene la lista con los documentos actualmente
disponibles de la <a href="./">Versi&oacute;n 2.4 de la
Documentaci&oacute;n del Servidor HTTP Apache</a>.</p>
</div>
<div id="quickview"><ul id="toc">
<li><img alt="" src="./images/down.gif"> <a href="#release">Notas de la Versi&oacute;n</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#using">Funcionamiento del Servidor HTTP Apache</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#vhosts">Documentaci&oacute;n sobre Hosting Virtual en Apache</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#faq">Preguntas M&aacute;s Frecuentes sobre Apache</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#ssl">Encriptado SSL/TLS con Apache</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#howto">Gu&iacute;as, Tutoriales, y HowTos</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#platform">Notas espec&iacute;ficas sobre plataformas</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#programs">Programas de soporte y el Servidor HTTP Apache</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#misc">Documentaci&oacute;n adicional sobre Apache</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#modules">M&oacute;dulos de Apache</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#developer">Documentaci&oacute;n para desarrolladores</a></li>
<li><img alt="" src="./images/down.gif"> <a href="#index">Glosario e &Iacute;ndice</a></li>
</ul>
</div>
<div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="release" id="release">Notas de la Versi&oacute;n</a></h2>
<ul><li><a href="upgrading.html">Pasar a usar Apache 2.0 desde Apache 1.3</a></li>
<li><a href="new_features_2_0.html">Nuevas funcionalidades de Apache 2.0</a></li>
<li><a href="license.html">Licencia Apache</a></li>
</ul>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="using" id="using">Funcionamiento del Servidor HTTP Apache</a></h2>
<ul><li><a href="install.html">Compilaci&oacute;n e Instalaci&oacute;n de Apache</a></li>
<li><a href="invoking.html">Iniciar Apache</a></li>
<li><a href="stopping.html">Parar y reiniciar Apache</a></li>
<li><a href="configuring.html">Ficheros de Configuraci&oacute;n</a></li>
<li><a href="sections.html">Funcionamiento de las secciones Directory, Location y Files</a></li>
<li><a href="server-wide.html">Configuraci&oacute;n B&aacute;sica de Apache</a></li>
<li><a href="logs.html">Archivos Log</a></li>
<li><a href="urlmapping.html">Mapear URLs a ubicaciones de un sistema de ficheros</a></li>
<li><a href="misc/security_tips.html">Consejos de Seguridad</a></li>
<li><a href="dso.html">Soporte de Objetos Din&aacute;micos Compartidos (DSO)</a></li>
<li><a href="content-negotiation.html">Negociaci&oacute;n de Contenido</a></li>
<li><a href="custom-error.html">Mensajes de Error Personalizados</a></li>
<li><a href="bind.html">Fijar las direcciones y los puertos que usa Apache</a></li>
<li><a href="mpm.html">M&oacute;dulos de Multiproceso (MPMs)</a></li>
<li><a href="env.html">Variables de entorno en Apache</a></li>
<li><a href="handler.html">El uso de Handlers en Apache</a></li>
<li><a href="filter.html">Filtros</a></li>
<li><a href="suexec.html">Soporte de suEXEC</a></li>
<li><a href="misc/perf-tuning.html">Rendimiento del servidor</a></li>
<li><a href="misc/rewriteguide.html">Documentaci&oacute;n adicional sobre mod_rewrite</a></li>
</ul>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="vhosts" id="vhosts">Documentaci&oacute;n sobre Hosting Virtual en Apache</a></h2>
<ul><li class="separate"><a href="vhosts/">Visi&oacute;n General</a></li>
<li><a href="vhosts/name-based.html">Hosting Virtual basado en nombres</a></li>
<li><a href="vhosts/ip-based.html">Soporte de Hosting Virtual Basado en IPs</a></li>
<li><a href="vhosts/mass.html">Configurar de forma Din&aacute;mica el Hosting Virtual masivo en Apache</a></li>
<li><a href="vhosts/examples.html">Ejemplos de Hosting Virtual</a></li>
<li><a href="vhosts/details.html">Discusi&oacute;n en profundidad sobre los tipos de Hosting Virtual</a></li>
<li><a href="vhosts/fd-limits.html">Limitaciones de los descriptores de ficheros</a></li>
<li><a href="dns-caveats.html">Asuntos relacionados con DNS y Apache</a></li>
</ul>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="faq" id="faq">Preguntas M&aacute;s Frecuentes sobre Apache</a></h2>
<ul><li><a href="faq/">Visi&oacute;n General</a></li>
<li><a href="faq/support.html">Soporte</a></li>
<li><a href="faq/error.html">Mensajes de error</a></li>
</ul>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="ssl" id="ssl">Encriptado SSL/TLS con Apache</a></h2>
<ul><li class="separate"><a href="ssl/">Visi&oacute;n General</a></li>
<li><a href="ssl/ssl_intro.html">Encriptado SSL/TLS: Introducci&oacute;n</a></li>
<li><a href="ssl/ssl_compat.html">Encriptado SSL/TLS: Compatibilidad</a></li>
<li><a href="ssl/ssl_howto.html">Encriptado SSL/TLS: How-To</a></li>
<li><a href="ssl/ssl_faq.html">Encriptado SSL/TLS: Preguntas Frecuentes</a></li>
</ul>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="howto" id="howto">Gu&iacute;as, Tutoriales, y HowTos</a></h2>
<ul><li class="separate"><a href="howto/">Visi&oacute;n General</a></li>
<li><a href="howto/auth.html">Autentificaci&oacute;n</a></li>
<li><a href="howto/cgi.html">Contenido Din&aacute;mico con CGIs</a></li>
<li><a href="howto/ssi.html">Introducci&oacute;n a Server Side Includes</a></li>
<li><a href="howto/htaccess.html">Archivos .htaccess</a></li>
<li><a href="howto/public_html.html">Directorios web para cada usuario</a></li>
</ul>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="platform" id="platform">Notas espec&iacute;ficas sobre plataformas</a></h2>
<ul><li class="separate"><a href="platform/">Visi&oacute;n General</a></li>
<li><a href="platform/windows.html">Usar Apache con Microsoft Windows</a></li>
<li><a href="platform/win_compiling.html">Compilar Apache para
Microsoft Windows</a></li>
<li><a href="platform/netware.html">Usar
Apache con Novell NetWare</a></li>
<li><a href="platform/perf-hp.html">Servidor Web de alto rendimiento con
HPUX</a></li>
<li><a href="platform/ebcdic.html">La versi&oacute;n EBCDIC de
Apache</a></li>
</ul>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="programs" id="programs">Programas de soporte y el Servidor HTTP Apache</a></h2>
<ul><li class="separate"><a href="programs/">Visi&oacute;n General</a></li>
<li><a href="programs/httpd.html">P&aacute;gina de Ayuda: httpd</a></li>
<li><a href="programs/ab.html">P&aacute;gina de Ayuda: ab</a></li>
<li><a href="programs/apachectl.html">P&aacute;gina de Ayuda: apachectl</a></li>
<li><a href="programs/apxs.html">P&aacute;gina de Ayuda: apxs</a></li>
<li><a href="programs/configure.html">P&aacute;gina de Ayuda: configure</a></li>
<li><a href="programs/dbmmanage.html">P&aacute;gina de Ayuda: dbmmanage</a></li>
<li><a href="programs/htcacheclean.html">P&aacute;gina de Ayuda: htcacheclean</a></li>
<li><a href="programs/htdigest.html">P&aacute;gina de Ayuda: htdigest</a></li>
<li><a href="programs/htpasswd.html">P&aacute;gina de Ayuda: htpasswd</a></li>
<li><a href="programs/logresolve.html">P&aacute;gina de Ayuda: logresolve</a></li>
<li><a href="programs/rotatelogs.html">P&aacute;gina de Ayuda: rotatelogs</a></li>
<li><a href="programs/suexec.html">P&aacute;gina de Ayuda: suexec</a></li>
<li><a href="programs/other.html">Otros Programas</a></li>
</ul>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="misc" id="misc">Documentaci&oacute;n adicional sobre Apache</a></h2>
<ul><li class="separate"><a href="misc/">Visi&oacute;n General</a></li>
<li><a href="misc/relevant_standards.html">Est&aacute;ndares Importantes</a></li>
</ul>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="modules" id="modules">M&oacute;dulos de Apache</a></h2>
<ul><li><a href="mod/module-dict.html">Definiciones de t&eacute;rminos usados
para describir los m&oacute;dulos de Apache</a></li>
<li><a href="mod/directive-dict.html">Definiciones de t&eacute;rminos
usados para describir las directivas de Apache</a></li>
</ul><ul><li><a href="mod/core.html">Funcionalidad B&aacute;sica de Apache</a></li>
<li><a href="mod/mpm_common.html">Directivas Comunes de los MPM de
            Apache</a></li>
<li><a href="mod/event.html">MPM de Apache event</a></li>
<li><a href="mod/mpm_netware.html">MPM de Apache netware</a></li>
<li><a href="mod/mpmt_os2.html">MPM de Apache os2</a></li>
<li><a href="mod/prefork.html">MPM de Apache prefork</a></li>
<li><a href="mod/mpm_winnt.html">MPM de Apache winnt</a></li>
<li><a href="mod/worker.html">MPM de Apache worker</a></li>
</ul><ul><li><a href="mod/mod_access_compat.html">M&oacute;dulo Apache mod_access_compat</a></li>
<li><a href="mod/mod_actions.html">M&oacute;dulo Apache mod_actions</a></li>
<li><a href="mod/mod_alias.html">M&oacute;dulo Apache mod_alias</a></li>
<li><a href="mod/mod_allowmethods.html">M&oacute;dulo Apache mod_allowmethods</a></li>
<li><a href="mod/mod_asis.html">M&oacute;dulo Apache mod_asis</a></li>
<li><a href="mod/mod_auth_basic.html">M&oacute;dulo Apache mod_auth_basic</a></li>
<li><a href="mod/mod_auth_digest.html">M&oacute;dulo Apache mod_auth_digest</a></li>
<li><a href="mod/mod_auth_form.html">M&oacute;dulo Apache mod_auth_form</a></li>
<li><a href="mod/mod_authn_anon.html">M&oacute;dulo Apache mod_authn_anon</a></li>
<li><a href="mod/mod_authn_core.html">M&oacute;dulo Apache mod_authn_core</a></li>
<li><a href="mod/mod_authn_dbd.html">M&oacute;dulo Apache mod_authn_dbd</a></li>
<li><a href="mod/mod_authn_dbm.html">M&oacute;dulo Apache mod_authn_dbm</a></li>
<li><a href="mod/mod_authn_file.html">M&oacute;dulo Apache mod_authn_file</a></li>
<li><a href="mod/mod_authn_socache.html">M&oacute;dulo Apache mod_authn_socache</a></li>
<li><a href="mod/mod_authnz_fcgi.html">M&oacute;dulo Apache mod_authnz_fcgi</a></li>
<li><a href="mod/mod_authnz_ldap.html">M&oacute;dulo Apache mod_authnz_ldap</a></li>
<li><a href="mod/mod_authz_core.html">M&oacute;dulo Apache mod_authz_core</a></li>
<li><a href="mod/mod_authz_dbd.html">M&oacute;dulo Apache mod_authz_dbd</a></li>
<li><a href="mod/mod_authz_dbm.html">M&oacute;dulo Apache mod_authz_dbm</a></li>
<li><a href="mod/mod_authz_groupfile.html">M&oacute;dulo Apache mod_authz_groupfile</a></li>
<li><a href="mod/mod_authz_host.html">M&oacute;dulo Apache mod_authz_host</a></li>
<li><a href="mod/mod_authz_owner.html">M&oacute;dulo Apache mod_authz_owner</a></li>
<li><a href="mod/mod_authz_user.html">M&oacute;dulo Apache mod_authz_user</a></li>
<li><a href="mod/mod_autoindex.html">M&oacute;dulo Apache mod_autoindex</a></li>
<li><a href="mod/mod_brotli.html">M&oacute;dulo Apache mod_brotli</a></li>
<li><a href="mod/mod_buffer.html">M&oacute;dulo Apache mod_buffer</a></li>
<li><a href="mod/mod_cache.html">M&oacute;dulo Apache mod_cache</a></li>
<li><a href="mod/mod_cache_disk.html">M&oacute;dulo Apache mod_cache_disk</a></li>
<li><a href="mod/mod_cache_socache.html">M&oacute;dulo Apache mod_cache_socache</a></li>
<li><a href="mod/mod_cern_meta.html">M&oacute;dulo Apache mod_cern_meta</a></li>
<li><a href="mod/mod_cgi.html">M&oacute;dulo Apache mod_cgi</a></li>
<li><a href="mod/mod_cgid.html">M&oacute;dulo Apache mod_cgid</a></li>
<li><a href="mod/mod_charset_lite.html">M&oacute;dulo Apache mod_charset_lite</a></li>
<li><a href="mod/mod_data.html">M&oacute;dulo Apache mod_data</a></li>
<li><a href="mod/mod_dav.html">M&oacute;dulo Apache mod_dav</a></li>
<li><a href="mod/mod_dav_fs.html">M&oacute;dulo Apache mod_dav_fs</a></li>
<li><a href="mod/mod_dav_lock.html">M&oacute;dulo Apache mod_dav_lock</a></li>
<li><a href="mod/mod_dbd.html">M&oacute;dulo Apache mod_dbd</a></li>
<li><a href="mod/mod_deflate.html">M&oacute;dulo Apache mod_deflate</a></li>
<li><a href="mod/mod_dialup.html">M&oacute;dulo Apache mod_dialup</a></li>
<li><a href="mod/mod_dir.html">M&oacute;dulo Apache mod_dir</a></li>
<li><a href="mod/mod_dumpio.html">M&oacute;dulo Apache mod_dumpio</a></li>
<li><a href="mod/mod_echo.html">M&oacute;dulo Apache mod_echo</a></li>
<li><a href="mod/mod_env.html">M&oacute;dulo Apache mod_env</a></li>
<li><a href="mod/mod_example_hooks.html">M&oacute;dulo Apache mod_example_hooks</a></li>
<li><a href="mod/mod_expires.html">M&oacute;dulo Apache mod_expires</a></li>
<li><a href="mod/mod_ext_filter.html">M&oacute;dulo Apache mod_ext_filter</a></li>
<li><a href="mod/mod_file_cache.html">M&oacute;dulo Apache mod_file_cache</a></li>
<li><a href="mod/mod_filter.html">M&oacute;dulo Apache mod_filter</a></li>
<li><a href="mod/mod_headers.html">M&oacute;dulo Apache mod_headers</a></li>
<li><a href="mod/mod_heartbeat.html">M&oacute;dulo Apache mod_heartbeat</a></li>
<li><a href="mod/mod_heartmonitor.html">M&oacute;dulo Apache mod_heartmonitor</a></li>
<li><a href="mod/mod_http2.html">M&oacute;dulo Apache mod_http2</a></li>
<li><a href="mod/mod_ident.html">M&oacute;dulo Apache mod_ident</a></li>
<li><a href="mod/mod_imagemap.html">M&oacute;dulo Apache mod_imagemap</a></li>
<li><a href="mod/mod_include.html">M&oacute;dulo Apache mod_include</a></li>
<li><a href="mod/mod_info.html">M&oacute;dulo Apache mod_info</a></li>
<li><a href="mod/mod_isapi.html">M&oacute;dulo Apache mod_isapi</a></li>
<li><a href="mod/mod_lbmethod_bybusyness.html">M&oacute;dulo Apache mod_lbmethod_bybusyness</a></li>
<li><a href="mod/mod_lbmethod_byrequests.html">M&oacute;dulo Apache mod_lbmethod_byrequests</a></li>
<li><a href="mod/mod_lbmethod_bytraffic.html">M&oacute;dulo Apache mod_lbmethod_bytraffic</a></li>
<li><a href="mod/mod_lbmethod_heartbeat.html">M&oacute;dulo Apache mod_lbmethod_heartbeat</a></li>
<li><a href="mod/mod_ldap.html">M&oacute;dulo Apache mod_ldap</a></li>
<li><a href="mod/mod_log_config.html">M&oacute;dulo Apache mod_log_config</a></li>
<li><a href="mod/mod_log_debug.html">M&oacute;dulo Apache mod_log_debug</a></li>
<li><a href="mod/mod_log_forensic.html">M&oacute;dulo Apache mod_log_forensic</a></li>
<li><a href="mod/mod_logio.html">M&oacute;dulo Apache mod_logio</a></li>
<li><a href="mod/mod_lua.html">M&oacute;dulo Apache mod_lua</a></li>
<li><a href="mod/mod_macro.html">M&oacute;dulo Apache mod_macro</a></li>
<li><a href="mod/mod_md.html">M&oacute;dulo Apache mod_md</a></li>
<li><a href="mod/mod_mime.html">M&oacute;dulo Apache mod_mime</a></li>
<li><a href="mod/mod_mime_magic.html">M&oacute;dulo Apache mod_mime_magic</a></li>
<li><a href="mod/mod_negotiation.html">M&oacute;dulo Apache mod_negotiation</a></li>
<li><a href="mod/mod_nw_ssl.html">M&oacute;dulo Apache mod_nw_ssl</a></li>
<li><a href="mod/mod_privileges.html">M&oacute;dulo Apache mod_privileges</a></li>
<li><a href="mod/mod_proxy.html">M&oacute;dulo Apache mod_proxy</a></li>
<li><a href="mod/mod_proxy_ajp.html">M&oacute;dulo Apache mod_proxy_ajp</a></li>
<li><a href="mod/mod_proxy_balancer.html">M&oacute;dulo Apache mod_proxy_balancer</a></li>
<li><a href="mod/mod_proxy_connect.html">M&oacute;dulo Apache mod_proxy_connect</a></li>
<li><a href="mod/mod_proxy_express.html">M&oacute;dulo Apache mod_proxy_express</a></li>
<li><a href="mod/mod_proxy_fcgi.html">M&oacute;dulo Apache mod_proxy_fcgi</a></li>
<li><a href="mod/mod_proxy_fdpass.html">M&oacute;dulo Apache mod_proxy_fdpass</a></li>
<li><a href="mod/mod_proxy_ftp.html">M&oacute;dulo Apache mod_proxy_ftp</a></li>
<li><a href="mod/mod_proxy_hcheck.html">M&oacute;dulo Apache mod_proxy_hcheck</a></li>
<li><a href="mod/mod_proxy_html.html">M&oacute;dulo Apache mod_proxy_html</a></li>
<li><a href="mod/mod_proxy_http.html">M&oacute;dulo Apache mod_proxy_http</a></li>
<li><a href="mod/mod_proxy_http2.html">M&oacute;dulo Apache mod_proxy_http2</a></li>
<li><a href="mod/mod_proxy_scgi.html">M&oacute;dulo Apache mod_proxy_scgi</a></li>
<li><a href="mod/mod_proxy_uwsgi.html">M&oacute;dulo Apache mod_proxy_uwsgi</a></li>
<li><a href="mod/mod_proxy_wstunnel.html">M&oacute;dulo Apache mod_proxy_wstunnel</a></li>
<li><a href="mod/mod_ratelimit.html">M&oacute;dulo Apache mod_ratelimit</a></li>
<li><a href="mod/mod_reflector.html">M&oacute;dulo Apache mod_reflector</a></li>
<li><a href="mod/mod_remoteip.html">M&oacute;dulo Apache mod_remoteip</a></li>
<li><a href="mod/mod_reqtimeout.html">M&oacute;dulo Apache mod_reqtimeout</a></li>
<li><a href="mod/mod_request.html">M&oacute;dulo Apache mod_request</a></li>
<li><a href="mod/mod_rewrite.html">M&oacute;dulo Apache mod_rewrite</a></li>
<li><a href="mod/mod_sed.html">M&oacute;dulo Apache mod_sed</a></li>
<li><a href="mod/mod_session.html">M&oacute;dulo Apache mod_session</a></li>
<li><a href="mod/mod_session_cookie.html">M&oacute;dulo Apache mod_session_cookie</a></li>
<li><a href="mod/mod_session_crypto.html">M&oacute;dulo Apache mod_session_crypto</a></li>
<li><a href="mod/mod_session_dbd.html">M&oacute;dulo Apache mod_session_dbd</a></li>
<li><a href="mod/mod_setenvif.html">M&oacute;dulo Apache mod_setenvif</a></li>
<li><a href="mod/mod_slotmem_plain.html">M&oacute;dulo Apache mod_slotmem_plain</a></li>
<li><a href="mod/mod_slotmem_shm.html">M&oacute;dulo Apache mod_slotmem_shm</a></li>
<li><a href="mod/mod_so.html">M&oacute;dulo Apache mod_so</a></li>
<li><a href="mod/mod_socache_dbm.html">M&oacute;dulo Apache mod_socache_dbm</a></li>
<li><a href="mod/mod_socache_dc.html">M&oacute;dulo Apache mod_socache_dc</a></li>
<li><a href="mod/mod_socache_memcache.html">M&oacute;dulo Apache mod_socache_memcache</a></li>
<li><a href="mod/mod_socache_redis.html">M&oacute;dulo Apache mod_socache_redis</a></li>
<li><a href="mod/mod_socache_shmcb.html">M&oacute;dulo Apache mod_socache_shmcb</a></li>
<li><a href="mod/mod_speling.html">M&oacute;dulo Apache mod_speling</a></li>
<li><a href="mod/mod_ssl.html">M&oacute;dulo Apache mod_ssl</a></li>
<li><a href="mod/mod_status.html">M&oacute;dulo Apache mod_status</a></li>
<li><a href="mod/mod_substitute.html">M&oacute;dulo Apache mod_substitute</a></li>
<li><a href="mod/mod_suexec.html">M&oacute;dulo Apache mod_suexec</a></li>
<li><a href="mod/mod_systemd.html">M&oacute;dulo Apache mod_systemd</a></li>
<li><a href="mod/mod_unique_id.html">M&oacute;dulo Apache mod_unique_id</a></li>
<li><a href="mod/mod_unixd.html">M&oacute;dulo Apache mod_unixd</a></li>
<li><a href="mod/mod_userdir.html">M&oacute;dulo Apache mod_userdir</a></li>
<li><a href="mod/mod_usertrack.html">M&oacute;dulo Apache mod_usertrack</a></li>
<li><a href="mod/mod_version.html">M&oacute;dulo Apache mod_version</a></li>
<li><a href="mod/mod_vhost_alias.html">M&oacute;dulo Apache mod_vhost_alias</a></li>
<li><a href="mod/mod_watchdog.html">M&oacute;dulo Apache mod_watchdog</a></li>
<li><a href="mod/mod_xml2enc.html">M&oacute;dulo Apache mod_xml2enc</a></li>
</ul>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="developer" id="developer">Documentaci&oacute;n para desarrolladores</a></h2>
<ul><li class="separate"><a href="developer/">Visi&oacute;n General</a></li>
<li><a href="developer/API.html">Notas sobre la API de Apache</a></li>
<li><a href="developer/debugging.html">Debugear la Reserva de Memoria en APR</a></li>
<li><a href="developer/documenting.html">Documentando Apache 2.0</a></li>
<li><a href="developer/hooks.html">Funciones Hook de Apache 2.0</a></li>
<li><a href="developer/modules.html">Convertir M&oacute;dulos de Apache 1.3 a Apache 2.0</a></li>
<li><a href="developer/request.html">Procesamiento de Peticiones en Apache 2.0</a></li>
<li><a href="developer/filters.html">Funcionamiento de los filtros en Apache 2.0</a></li>
</ul>
</div><div class="top"><a href="#page-header"><img alt="top" src="./images/up.gif"></a></div>
<div class="section"><h2><a name="index" id="index">Glosario e &Iacute;ndice</a></h2>
<ul><li><a href="glossary.html">Glosario</a></li>
<li><a href="mod/">&Iacute;ndice de M&oacute;dulos</a></li>
<li><a href="mod/directives.html">&Iacute;ndice de Directivas</a></li>
<li><a href="mod/quickreference.html">Gu&iacute;a R&aacute;pida de
Referencia de Directivas</a></li>
</ul>
</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="./de/sitemap.html" hreflang="de" rel="alternate" title="Deutsch">&nbsp;de&nbsp;</a> |
<a href="./en/sitemap.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="./es/sitemap.html" title="Espa&ntilde;ol">&nbsp;es&nbsp;</a> |
<a href="./fr/sitemap.html" hreflang="fr" rel="alternate" title="Fran&ccedil;ais">&nbsp;fr&nbsp;</a> |
<a href="./ja/sitemap.html" hreflang="ja" rel="alternate" title="Japanese">&nbsp;ja&nbsp;</a> |
<a href="./ko/sitemap.html" hreflang="ko" rel="alternate" title="Korean">&nbsp;ko&nbsp;</a> |
<a href="./tr/sitemap.html" hreflang="tr" rel="alternate" title="T&uuml;rk&ccedil;e">&nbsp;tr&nbsp;</a> |
<a href="./zh-cn/sitemap.html" hreflang="zh-cn" rel="alternate" title="Simplified Chinese">&nbsp;zh-cn&nbsp;</a></p>
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