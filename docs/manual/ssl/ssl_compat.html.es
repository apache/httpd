<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Cifrado Robusto SSL/TLS: Compatibilidad  - Servidor HTTP Apache Versión 2.5</title>
<link href="../style/css/manual.css" rel="stylesheet" media="all" type="text/css" title="Main stylesheet" />
<link href="../style/css/manual-loose-100pc.css" rel="alternate stylesheet" media="all" type="text/css" title="No Sidebar - Default font size" />
<link href="../style/css/manual-print.css" rel="stylesheet" media="print" type="text/css" /><link rel="stylesheet" type="text/css" href="../style/css/prettify.css" />
<script src="../style/scripts/prettify.min.js" type="text/javascript">
</script>

<link href="../images/favicon.ico" rel="shortcut icon" /></head>
<body id="manual-page"><div id="page-header">
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p>
<p class="apache">Versión 2.5 del Servidor HTTP Apache</p>
<img alt="" src="../images/feather.png" /></div>
<div class="up"><a href="./"><img title="&lt;-" alt="&lt;-" src="../images/left.gif" /></a></div>
<div id="path">
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="../">Versión 2.5</a> &gt; <a href="./">SSL/TLS</a></div><div id="page-content"><div id="preamble"><h1>Cifrado Robusto SSL/TLS: Compatibilidad </h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/ssl/ssl_compat.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/ssl/ssl_compat.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/ssl/ssl_compat.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a></p>
</div>

<p>
En esta página se cubre la compatibilidad entre el módulo <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code>
y otras soluciones SSL.
<code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code> no es la única solución de SSL para Apache HTTPD Server;
Para productos adicionales que están (o estaban) disponibles como Ben Laurie's
en su web, que ahora no existe (http://www.apache-ssl.org/), donde fue la 
derivación original en 1998 del módulo.
Tanto el sistema de <a href="https://www.redhat.com/archives/redhat-secure-server/"> Red Hat 
Secure Web Server </a> se basó en mod_ssl así como la versión comercial del
<a href="https://lists.freebsd.org/pipermail/freebsd-announce/1998-March/000403.html">
 módulo SSL de Covalent's Raven</a>, y por último, C2Net (ahora de Red Hat)
 basado en una rama de evaluación del proyecto llamado Sioux con un 
 "Stronghold 2.x" y basado en mod_ssl desde la versión "Stronghold 3.x".

 

</p>

<p>
mod_ssl proporciona un superconjunto de la funcionalidad de todas las demás
soluciones, por lo que será simple la migración de módulos antiguos al 
<code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code>.
Las directivas de configuración y nombres de variables de entorno usadas 
por módulos antiguos de SSL varían mucho de mod_ssl;
tablas de correspondencia con lo usado por mod_ssl, se detallan a continuación.
</p>
</div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#configuration">Directivas de Configuración</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#variables">Variables de Entorno</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#customlog">Funciones Personalizadas de Log</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="configuration" id="configuration">Directivas de Configuración</a></h2>
<p>La correspondencia entre las directivas de configuración usadas por
Apache-SSL 1.x y mod_ssl 2.0.x se dan en la <a href="#table1">Tabla
1</a>. La correspondencia de Sioux 1.x y Stronghold 2.x es solo parcial 
debido a funcionalidades especiales en estas interfaces que mod_ssl no proporciona.
</p>


<h3><a name="table1" id="table1">Table 1: Correspondencia de Directivas de Configuración</a></h3>

<table><tr class="header"><th>Directivas Antiguas</th><th>Directivas mod_ssl </th><th>Comentarios</th></tr>
<tr class="header"><th colspan="3">Compatibilidad de Apache-SSL 1.x &amp; mod_ssl 2.0.x:</th></tr>
<tr><td><code>SSLEnable</code></td><td><code>SSLEngine on</code></td><td>compactified</td></tr>
<tr class="odd"><td><code>SSLDisable</code></td><td><code>SSLEngine off</code></td><td>compactified</td></tr>
<tr><td><code>SSLLogFile</code> <em>fichero</em></td><td><code /></td><td>Use per-module <code class="directive"><a href="../mod/core.html#loglevel">LogLevel</a></code> setting instead.</td></tr>
<tr class="odd"><td><code>SSLRequiredCiphers</code> <em>spec</em></td><td><code>SSLCipherSuite</code> <em>spec</em></td><td>renombrada</td></tr>
<tr><td><code>SSLRequireCipher</code> <em>c1</em> ...</td><td><code>SSLRequire %{SSL_CIPHER} in {"</code><em>c1</em><code>",
...}</code></td><td>generalized</td></tr>
<tr class="odd"><td><code>SSLBanCipher</code> <em>c1</em> ...</td><td><code>SSLRequire not (%{SSL_CIPHER} in {"</code><em>c1</em><code>",
...})</code></td><td>generalized</td></tr>
<tr><td><code>SSLFakeBasicAuth</code></td><td><code>SSLOptions +FakeBasicAuth</code></td><td>merged</td></tr>
<tr class="odd"><td><code>SSLCacheServerPath</code> <em>dir</em></td><td>-</td><td>functionality removed</td></tr>
<tr><td><code>SSLCacheServerPort</code> <em>integer</em></td><td>-</td><td>functionality removed</td></tr>
<tr class="header"><th colspan="3">Compatibilidad Apache-SSL 1.x :</th></tr>
<tr class="odd"><td><code>SSLExportClientCertificates</code></td><td><code>SSLOptions +ExportCertData</code></td><td>merged</td></tr>
<tr><td><code>SSLCacheServerRunDir</code> <em>dir</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr class="header"><th colspan="3">Compatibilidad Sioux 1.x :</th></tr>
<tr class="odd"><td><code>SSL_CertFile</code> <em>fichero</em></td><td><code>SSLCertificateFile</code> <em>fichero</em></td><td>renombrada</td></tr>
<tr><td><code>SSL_KeyFile</code> <em>fichero</em></td><td><code>SSLCertificateKeyFile</code> <em>fichero</em></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_CipherSuite</code> <em>arg</em></td><td><code>SSLCipherSuite</code> <em>arg</em></td><td>renombrada</td></tr>
<tr><td><code>SSL_X509VerifyDir</code> <em>arg</em></td><td><code>SSLCACertificatePath</code> <em>arg</em></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_Log</code> <em>fichero</em></td><td><code>-</code></td><td>Use per-module <code class="directive"><a href="../mod/core.html#loglevel">LogLevel</a></code> setting instead.</td></tr>
<tr><td><code>SSL_Connect</code> <em>flag</em></td><td><code>SSLEngine</code> <em>flag</em></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_ClientAuth</code> <em>arg</em></td><td><code>SSLVerifyClient</code> <em>arg</em></td><td>renombrada</td></tr>
<tr><td><code>SSL_X509VerifyDepth</code> <em>arg</em></td><td><code>SSLVerifyDepth</code> <em>arg</em></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_FetchKeyPhraseFrom</code> <em>arg</em></td><td>-</td><td>not directly mappable; use SSLPassPhraseDialog</td></tr>
<tr><td><code>SSL_SessionDir</code> <em>dir</em></td><td>-</td><td>not directly mappable; use SSLSessionCache</td></tr>
<tr class="odd"><td><code>SSL_Require</code> <em>expr</em></td><td>-</td><td>not directly mappable; use SSLRequire</td></tr>
<tr><td><code>SSL_CertFileType</code> <em>arg</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr class="odd"><td><code>SSL_KeyFileType</code> <em>arg</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr><td><code>SSL_X509VerifyPolicy</code> <em>arg</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr class="odd"><td><code>SSL_LogX509Attributes</code> <em>arg</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr class="header"><th colspan="3">Compatibilidad Stronghold 2.x :</th></tr>
<tr><td><code>StrongholdAccelerator</code> <em>engine</em></td><td><code>SSLCryptoDevice</code> <em>engine</em></td><td>renombrada</td></tr>
<tr class="odd"><td><code>StrongholdKey</code> <em>dir</em></td><td>-</td><td>funcionalidad no requerida</td></tr>
<tr><td><code>StrongholdLicenseFile</code> <em>dir</em></td><td>-</td><td>funcionalidad no requerida</td></tr>
<tr class="odd"><td><code>SSLFlag</code> <em>flag</em></td><td><code>SSLEngine</code> <em>flag</em></td><td>renombrada</td></tr>
<tr><td><code>SSLSessionLockFile</code> <em>fichero</em></td><td><code>SSLMutex</code> <em>fichero</em></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSLCipherList</code> <em>spec</em></td><td><code>SSLCipherSuite</code> <em>spec</em></td><td>renombrada</td></tr>
<tr><td><code>RequireSSL</code></td><td><code>SSLRequireSSL</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSLErrorFile</code> <em>fichero</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr><td><code>SSLRoot</code> <em>dir</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr class="odd"><td><code>SSL_CertificateLogDir</code> <em>dir</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr><td><code>AuthCertDir</code> <em>dir</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr class="odd"><td><code>SSL_Group</code> <em>name</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr><td><code>SSLProxyMachineCertPath</code> <em>dir</em></td><td><code>SSLProxyMachineCertificatePath</code> <em>dir</em></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSLProxyMachineCertFile</code> <em>fichero</em></td><td><code>SSLProxyMachineCertificateFile</code> <em>fichero</em></td><td>renombrada</td></tr>
<tr><td><code>SSLProxyCipherList</code> <em>spec</em></td><td><code>SSLProxyCipherSpec</code> <em>spec</em></td><td>renombrada</td></tr>
</table>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="variables" id="variables">Variables de Entorno</a></h2>

<p>Correlación entre las variables de entorno usadas por soluciones antiguas de SSL y las usadas
por <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code> que se muestran en la <a href="#table2">Table 2</a>.</p>

<h3><a name="table2" id="table2">Tabla 2: Derivación de las Variables de Entorno</a></h3>

<table><tr class="header"><th>Variable Antigua</th><th>Variable mod_ssl</th><th>Comentario</th></tr>
<tr><td><code>SSL_PROTOCOL_VERSION</code></td><td><code>SSL_PROTOCOL</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSLEAY_VERSION</code></td><td><code>SSL_VERSION_LIBRARY</code></td><td>renombrada</td></tr>
<tr><td><code>HTTPS_SECRETKEYSIZE</code></td><td><code>SSL_CIPHER_USEKEYSIZE</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>HTTPS_KEYSIZE</code></td><td><code>SSL_CIPHER_ALGKEYSIZE</code></td><td>renombrada</td></tr>
<tr><td><code>HTTPS_CIPHER</code></td><td><code>SSL_CIPHER</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>HTTPS_EXPORT</code></td><td><code>SSL_CIPHER_EXPORT</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_KEY_SIZE</code></td><td><code>SSL_CIPHER_ALGKEYSIZE</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SERVER_CERTIFICATE</code></td><td><code>SSL_SERVER_CERT</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_CERT_START</code></td><td><code>SSL_SERVER_V_START</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SERVER_CERT_END</code></td><td><code>SSL_SERVER_V_END</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_CERT_SERIAL</code></td><td><code>SSL_SERVER_M_SERIAL</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SERVER_SIGNATURE_ALGORITHM</code></td><td><code>SSL_SERVER_A_SIG</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_DN</code></td><td><code>SSL_SERVER_S_DN</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SERVER_CN</code></td><td><code>SSL_SERVER_S_DN_CN</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_EMAIL</code></td><td><code>SSL_SERVER_S_DN_Email</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SERVER_O</code></td><td><code>SSL_SERVER_S_DN_O</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_OU</code></td><td><code>SSL_SERVER_S_DN_OU</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SERVER_C</code></td><td><code>SSL_SERVER_S_DN_C</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_SP</code></td><td><code>SSL_SERVER_S_DN_SP</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SERVER_L</code></td><td><code>SSL_SERVER_S_DN_L</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_IDN</code></td><td><code>SSL_SERVER_I_DN</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SERVER_ICN</code></td><td><code>SSL_SERVER_I_DN_CN</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_IEMAIL</code></td><td><code>SSL_SERVER_I_DN_Email</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SERVER_IO</code></td><td><code>SSL_SERVER_I_DN_O</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_IOU</code></td><td><code>SSL_SERVER_I_DN_OU</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SERVER_IC</code></td><td><code>SSL_SERVER_I_DN_C</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_ISP</code></td><td><code>SSL_SERVER_I_DN_SP</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SERVER_IL</code></td><td><code>SSL_SERVER_I_DN_L</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_CERTIFICATE</code></td><td><code>SSL_CLIENT_CERT</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_CLIENT_CERT_START</code></td><td><code>SSL_CLIENT_V_START</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_CERT_END</code></td><td><code>SSL_CLIENT_V_END</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_CLIENT_CERT_SERIAL</code></td><td><code>SSL_CLIENT_M_SERIAL</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_SIGNATURE_ALGORITHM</code></td><td><code>SSL_CLIENT_A_SIG</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_CLIENT_DN</code></td><td><code>SSL_CLIENT_S_DN</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_CN</code></td><td><code>SSL_CLIENT_S_DN_CN</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_CLIENT_EMAIL</code></td><td><code>SSL_CLIENT_S_DN_Email</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_O</code></td><td><code>SSL_CLIENT_S_DN_O</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_CLIENT_OU</code></td><td><code>SSL_CLIENT_S_DN_OU</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_C</code></td><td><code>SSL_CLIENT_S_DN_C</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_CLIENT_SP</code></td><td><code>SSL_CLIENT_S_DN_SP</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_L</code></td><td><code>SSL_CLIENT_S_DN_L</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_CLIENT_IDN</code></td><td><code>SSL_CLIENT_I_DN</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_ICN</code></td><td><code>SSL_CLIENT_I_DN_CN</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_CLIENT_IEMAIL</code></td><td><code>SSL_CLIENT_I_DN_Email</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_IO</code></td><td><code>SSL_CLIENT_I_DN_O</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_CLIENT_IOU</code></td><td><code>SSL_CLIENT_I_DN_OU</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_IC</code></td><td><code>SSL_CLIENT_I_DN_C</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_CLIENT_ISP</code></td><td><code>SSL_CLIENT_I_DN_SP</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_IL</code></td><td><code>SSL_CLIENT_I_DN_L</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_EXPORT</code></td><td><code>SSL_CIPHER_EXPORT</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_KEYSIZE</code></td><td><code>SSL_CIPHER_ALGKEYSIZE</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_SECKEYSIZE</code></td><td><code>SSL_CIPHER_USEKEYSIZE</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SSLEAY_VERSION</code></td><td><code>SSL_VERSION_LIBRARY</code></td><td>renombrada</td></tr>
<tr class="odd"><td><code>SSL_STRONG_CRYPTO</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_SERVER_KEY_EXP</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr class="odd"><td><code>SSL_SERVER_KEY_ALGORITHM</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_SERVER_KEY_SIZE</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr class="odd"><td><code>SSL_SERVER_SESSIONDIR</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_SERVER_CERTIFICATELOGDIR</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr class="odd"><td><code>SSL_SERVER_CERTFILE</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_SERVER_KEYFILE</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr class="odd"><td><code>SSL_SERVER_KEYFILETYPE</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_CLIENT_KEY_EXP</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr class="odd"><td><code>SSL_CLIENT_KEY_ALGORITHM</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_CLIENT_KEY_SIZE</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
</table>

</div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="customlog" id="customlog">Funciones Personalizadas de Log</a></h2>
<p>
Cuando está habilitado el módulo <code class="module"><a href="../mod/mod_ssl.html">mod_ssl</a></code>, existen funciones adicionales
para el <a href="../mod/mod_log_config.html#formats">Formato de Log Personalizado</a> 
<code class="module"><a href="../mod/mod_log_config.html">mod_log_config</a></code> como se documenta en el capítulo referenciado. 
Junto con  la función de formato de eXtensión ``<code>%{</code><em>varname</em><code>}x</code>''
la cual puede ser usada para extender cualquier variable proporcionada por cualquier módulo,
una función criptográfica de formato adicional 
``<code>%{</code><em>name</em><code>}c</code>'' cryptography format function
exists for backward compatibility. The currently implemented function calls
are listed in <a href="#table3">Table 3</a>.</p>

<h3><a name="table3" id="table3">Table 3: Funciones criptográficas de Log Personalizado</a></h3>

<table>

<tr><th>Llamada a la Función</th><th>Descripción</th></tr>

<tr><td><code>%...{version}c</code></td>   <td>SSL protocol version</td></tr>
<tr><td><code>%...{cipher}c</code></td>    <td>SSL cipher</td></tr>
<tr><td><code>%...{subjectdn}c</code></td> <td>Client Certificate Subject Distinguished Name</td></tr>
<tr><td><code>%...{issuerdn}c</code></td>  <td>Client Certificate Issuer Distinguished Name</td></tr>
<tr><td><code>%...{errcode}c</code></td>   <td>Certificate Verification Error (numerical)</td></tr>
<tr><td><code>%...{errstr}c</code></td>    <td>Certificate Verification Error (string)</td></tr>
</table>

</div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/ssl/ssl_compat.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/ssl/ssl_compat.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/ssl/ssl_compat.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/ssl/ssl_compat.html';
(function(w, d) {
    if (w.location.hostname.toLowerCase() == "httpd.apache.org") {
        d.write('<div id="comments_thread"><\/div>');
        var s = d.createElement('script');
        s.type = 'text/javascript';
        s.async = true;
        s.src = 'https://comments.apache.org/show_comments.lua?site=' + comments_shortname + '&page=' + comments_identifier;
        (d.getElementsByTagName('head')[0] || d.getElementsByTagName('body')[0]).appendChild(s);
    }
    else {
        d.write('<div id="comments_thread">Comments are disabled for this page at the moment.<\/div>');
    }
})(window, document);
//--><!]]></script></div><div id="footer">
<p class="apache">Copyright 2017 The Apache Software Foundation.<br />Licencia bajo los términos de la <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.</p>
<p class="menu"><a href="../mod/">Módulos</a> | <a href="../mod/quickreference.html">Directivas</a> | <a href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> | <a href="../glossary.html">Glosario</a> | <a href="../sitemap.html">Mapa del sitio web</a></p></div><script type="text/javascript"><!--//--><![CDATA[//><!--
if (typeof(prettyPrint) !== 'undefined') {
    prettyPrint();
}
//--><!]]></script>
</body></html>