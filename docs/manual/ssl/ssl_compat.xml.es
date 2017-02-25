<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.en.xsl"?>
<!-- English revision: 1200006 -->
<!-- Translated by Luis Gil de Bernabé Pfeiffer lgilbernabe[AT]apache.org -->
<!-- Reviewed by Sergio Ramos-->
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

<manualpage metafile="ssl_compat.xml.meta">
<parentdocument href="./">SSL/TLS</parentdocument>

  <title>Cifrado Robusto SSL/TLS: Compatibilidad </title>

<summary>
<p>
En esta página se cubre la compatibilidad entre el módulo <module>mod_ssl</module>
y otras soluciones SSL.
<module>mod_ssl</module> no es la única solución de SSL para Apache HTTPD Server;
Para productos adicionales que están (o estaban) disponibles como Ben Laurie's
en su web, que ahora no existe (http://www.apache-ssl.org/), donde fue la 
derivación original en 1998 del módulo.
Tanto el sistema de <a href="https://www.redhat.com/archives/redhat-secure-server/"> Red Hat 
Secure Web Server </a> se basó en mod_ssl así como la versión comercial del
<a href="https://lists.freebsd.org/pipermail/freebsd-announce/1998-March/000403.html">
 módulo SSL de Covalent's Raven</a>, y por último, C2Net (ahora de Red Hat)
 basado en una rama de evaluación del proyecto llamado Sioux con un 
 "Stronghold 2.x" y basado en mod_ssl desde la versión "Stronghold 3.x".

<!-- Issue for add to the bugzilla URL
https://www.google.es/url?sa=t&rct=j&q=&esrc=
s&source=web&cd=3&cad=rja&uact=
8&ved=0ahUKEwiDyun2p6bSAhVD2xoKHZowAToQFgg
5MAI&url=https%3A%2F%2Faccess.
redhat.com%2Fdocumentation%2Fen-US%
2FRed_Hat_Directory_Server%2F8.2%2Fhtml%2FAdministration_Guide%2FManaging_SSL.html
:--> 

</p>

<p>
mod_ssl proporciona un superconjunto de la funcionalidad de todas las demás
soluciones, por lo que será simple la migración de módulos antiguos al 
<module>mod_ssl</module>.
Las directivas de configuración y nombres de variables de entorno usadas 
por módulos antiguos de SSL varían mucho de mod_ssl;
tablas de correspondencia con lo usado por mod_ssl, se detallan a continuación.
</p>
</summary>

<section id="configuration"><title>Directivas de Configuración</title>
<p>La correspondencia entre las directivas de configuración usadas por
Apache-SSL 1.x y mod_ssl 2.0.x se dan en la <a href="#table1">Tabla
1</a>. La correspondencia de Sioux 1.x y Stronghold 2.x es solo parcial 
debido a funcionalidades especiales en estas interfaces que mod_ssl no proporciona.
</p>


<section id="table1">
<title>Table 1: Correspondencia de Directivas de Configuración</title>
<table style="zebra">
<columnspec><column width=".32"/><column width=".32"/>
<column width=".32"/></columnspec>
<tr><th>Directivas Antiguas</th><th>Directivas mod_ssl </th><th>Comentarios</th></tr>

<tr><th colspan="3">Compatibilidad de Apache-SSL 1.x &amp; mod_ssl 2.0.x:</th></tr>
<tr><td><code>SSLEnable</code></td><td><code>SSLEngine on</code></td><td>compactified</td></tr>
<tr><td><code>SSLDisable</code></td><td><code>SSLEngine off</code></td><td>compactified</td></tr>
<tr><td><code>SSLLogFile</code> <em>fichero</em></td><td><code></code></td><td>Use per-module <directive module="core">LogLevel</directive> setting instead.</td></tr>

<tr><td><code>SSLRequiredCiphers</code> <em>spec</em></td><td><code>SSLCipherSuite</code> <em>spec</em></td><td>renombrada</td></tr>
<tr><td><code>SSLRequireCipher</code> <em>c1</em> ...</td><td><code>SSLRequire %{SSL_CIPHER} in {"</code><em>c1</em><code>",
...}</code></td><td>generalized</td></tr>

<tr><td><code>SSLBanCipher</code> <em>c1</em> ...</td><td><code>SSLRequire not (%{SSL_CIPHER} in {"</code><em>c1</em><code>",
...})</code></td><td>generalized</td></tr>
<tr><td><code>SSLFakeBasicAuth</code></td><td><code>SSLOptions +FakeBasicAuth</code></td><td>merged</td></tr>
<tr><td><code>SSLCacheServerPath</code> <em>dir</em></td><td>-</td><td>functionality removed</td></tr>

<tr><td><code>SSLCacheServerPort</code> <em>integer</em></td><td>-</td><td>functionality removed</td></tr>
<tr><th colspan="3">Compatibilidad Apache-SSL 1.x :</th></tr>
<tr><td><code>SSLExportClientCertificates</code></td><td><code>SSLOptions +ExportCertData</code></td><td>merged</td></tr>
<tr><td><code>SSLCacheServerRunDir</code> <em>dir</em></td><td>-</td><td>funcionalidad no soportada</td></tr>

<tr><th colspan="3">Compatibilidad Sioux 1.x :</th></tr>
<tr><td><code>SSL_CertFile</code> <em>fichero</em></td><td><code>SSLCertificateFile</code> <em>fichero</em></td><td>renombrada</td></tr>
<tr><td><code>SSL_KeyFile</code> <em>fichero</em></td><td><code>SSLCertificateKeyFile</code> <em>fichero</em></td><td>renombrada</td></tr>

<tr><td><code>SSL_CipherSuite</code> <em>arg</em></td><td><code>SSLCipherSuite</code> <em>arg</em></td><td>renombrada</td></tr>
<tr><td><code>SSL_X509VerifyDir</code> <em>arg</em></td><td><code>SSLCACertificatePath</code> <em>arg</em></td><td>renombrada</td></tr>
<tr><td><code>SSL_Log</code> <em>fichero</em></td><td><code>-</code></td><td>Use per-module <directive module="core">LogLevel</directive> setting instead.</td></tr>

<tr><td><code>SSL_Connect</code> <em>flag</em></td><td><code>SSLEngine</code> <em>flag</em></td><td>renombrada</td></tr>
<tr><td><code>SSL_ClientAuth</code> <em>arg</em></td><td><code>SSLVerifyClient</code> <em>arg</em></td><td>renombrada</td></tr>
<tr><td><code>SSL_X509VerifyDepth</code> <em>arg</em></td><td><code>SSLVerifyDepth</code> <em>arg</em></td><td>renombrada</td></tr>

<tr><td><code>SSL_FetchKeyPhraseFrom</code> <em>arg</em></td><td>-</td><td>not directly mappable; use SSLPassPhraseDialog</td></tr>
<tr><td><code>SSL_SessionDir</code> <em>dir</em></td><td>-</td><td>not directly mappable; use SSLSessionCache</td></tr>
<tr><td><code>SSL_Require</code> <em>expr</em></td><td>-</td><td>not directly mappable; use SSLRequire</td></tr>

<tr><td><code>SSL_CertFileType</code> <em>arg</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr><td><code>SSL_KeyFileType</code> <em>arg</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr><td><code>SSL_X509VerifyPolicy</code> <em>arg</em></td><td>-</td><td>funcionalidad no soportada</td></tr>

<tr><td><code>SSL_LogX509Attributes</code> <em>arg</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr><th colspan="3">Compatibilidad Stronghold 2.x :</th></tr>
<tr><td><code>StrongholdAccelerator</code> <em>engine</em></td><td><code>SSLCryptoDevice</code> <em>engine</em></td><td>renombrada</td></tr>
<tr><td><code>StrongholdKey</code> <em>dir</em></td><td>-</td><td>funcionalidad no requerida</td></tr>

<tr><td><code>StrongholdLicenseFile</code> <em>dir</em></td><td>-</td><td>funcionalidad no requerida</td></tr>
<tr><td><code>SSLFlag</code> <em>flag</em></td><td><code>SSLEngine</code> <em>flag</em></td><td>renombrada</td></tr>
<tr><td><code>SSLSessionLockFile</code> <em>fichero</em></td><td><code>SSLMutex</code> <em>fichero</em></td><td>renombrada</td></tr>

<tr><td><code>SSLCipherList</code> <em>spec</em></td><td><code>SSLCipherSuite</code> <em>spec</em></td><td>renombrada</td></tr>
<tr><td><code>RequireSSL</code></td><td><code>SSLRequireSSL</code></td><td>renombrada</td></tr>
<tr><td><code>SSLErrorFile</code> <em>fichero</em></td><td>-</td><td>funcionalidad no soportada</td></tr>

<tr><td><code>SSLRoot</code> <em>dir</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr><td><code>SSL_CertificateLogDir</code> <em>dir</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr><td><code>AuthCertDir</code> <em>dir</em></td><td>-</td><td>funcionalidad no soportada</td></tr>

<tr><td><code>SSL_Group</code> <em>name</em></td><td>-</td><td>funcionalidad no soportada</td></tr>
<tr><td><code>SSLProxyMachineCertPath</code> <em>dir</em></td><td><code>SSLProxyMachineCertificatePath</code> <em>dir</em></td><td>renombrada</td></tr>
<tr><td><code>SSLProxyMachineCertFile</code> <em>fichero</em></td><td><code>SSLProxyMachineCertificateFile</code> <em>fichero</em></td><td>renombrada</td></tr>

<tr><td><code>SSLProxyCipherList</code> <em>spec</em></td><td><code>SSLProxyCipherSpec</code> <em>spec</em></td><td>renombrada</td></tr>
</table>
</section>
</section>

<section id="variables"><title>Variables de Entorno</title>

<p>Correlación entre las variables de entorno usadas por soluciones antiguas de SSL y las usadas
por <module>mod_ssl</module> que se muestran en la <a
href="#table2">Table 2</a>.</p>

<section id="table2">
<title>Tabla 2: Derivación de las Variables de Entorno</title>
<table style="zebra">
<columnspec><column width=".38"/><column width=".38"/>
<column width=".2"/></columnspec>
<tr><th>Variable Antigua</th><th>Variable mod_ssl</th><th>Comentario</th></tr>

<tr><td><code>SSL_PROTOCOL_VERSION</code></td><td><code>SSL_PROTOCOL</code></td><td>renombrada</td></tr>
<tr><td><code>SSLEAY_VERSION</code></td><td><code>SSL_VERSION_LIBRARY</code></td><td>renombrada</td></tr>
<tr><td><code>HTTPS_SECRETKEYSIZE</code></td><td><code>SSL_CIPHER_USEKEYSIZE</code></td><td>renombrada</td></tr>
<tr><td><code>HTTPS_KEYSIZE</code></td><td><code>SSL_CIPHER_ALGKEYSIZE</code></td><td>renombrada</td></tr>
<tr><td><code>HTTPS_CIPHER</code></td><td><code>SSL_CIPHER</code></td><td>renombrada</td></tr>

<tr><td><code>HTTPS_EXPORT</code></td><td><code>SSL_CIPHER_EXPORT</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_KEY_SIZE</code></td><td><code>SSL_CIPHER_ALGKEYSIZE</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_CERTIFICATE</code></td><td><code>SSL_SERVER_CERT</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_CERT_START</code></td><td><code>SSL_SERVER_V_START</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_CERT_END</code></td><td><code>SSL_SERVER_V_END</code></td><td>renombrada</td></tr>

<tr><td><code>SSL_SERVER_CERT_SERIAL</code></td><td><code>SSL_SERVER_M_SERIAL</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_SIGNATURE_ALGORITHM</code></td><td><code>SSL_SERVER_A_SIG</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_DN</code></td><td><code>SSL_SERVER_S_DN</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_CN</code></td><td><code>SSL_SERVER_S_DN_CN</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_EMAIL</code></td><td><code>SSL_SERVER_S_DN_Email</code></td><td>renombrada</td></tr>

<tr><td><code>SSL_SERVER_O</code></td><td><code>SSL_SERVER_S_DN_O</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_OU</code></td><td><code>SSL_SERVER_S_DN_OU</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_C</code></td><td><code>SSL_SERVER_S_DN_C</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_SP</code></td><td><code>SSL_SERVER_S_DN_SP</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_L</code></td><td><code>SSL_SERVER_S_DN_L</code></td><td>renombrada</td></tr>

<tr><td><code>SSL_SERVER_IDN</code></td><td><code>SSL_SERVER_I_DN</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_ICN</code></td><td><code>SSL_SERVER_I_DN_CN</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_IEMAIL</code></td><td><code>SSL_SERVER_I_DN_Email</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_IO</code></td><td><code>SSL_SERVER_I_DN_O</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_IOU</code></td><td><code>SSL_SERVER_I_DN_OU</code></td><td>renombrada</td></tr>

<tr><td><code>SSL_SERVER_IC</code></td><td><code>SSL_SERVER_I_DN_C</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_ISP</code></td><td><code>SSL_SERVER_I_DN_SP</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SERVER_IL</code></td><td><code>SSL_SERVER_I_DN_L</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_CERTIFICATE</code></td><td><code>SSL_CLIENT_CERT</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_CERT_START</code></td><td><code>SSL_CLIENT_V_START</code></td><td>renombrada</td></tr>

<tr><td><code>SSL_CLIENT_CERT_END</code></td><td><code>SSL_CLIENT_V_END</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_CERT_SERIAL</code></td><td><code>SSL_CLIENT_M_SERIAL</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_SIGNATURE_ALGORITHM</code></td><td><code>SSL_CLIENT_A_SIG</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_DN</code></td><td><code>SSL_CLIENT_S_DN</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_CN</code></td><td><code>SSL_CLIENT_S_DN_CN</code></td><td>renombrada</td></tr>

<tr><td><code>SSL_CLIENT_EMAIL</code></td><td><code>SSL_CLIENT_S_DN_Email</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_O</code></td><td><code>SSL_CLIENT_S_DN_O</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_OU</code></td><td><code>SSL_CLIENT_S_DN_OU</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_C</code></td><td><code>SSL_CLIENT_S_DN_C</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_SP</code></td><td><code>SSL_CLIENT_S_DN_SP</code></td><td>renombrada</td></tr>

<tr><td><code>SSL_CLIENT_L</code></td><td><code>SSL_CLIENT_S_DN_L</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_IDN</code></td><td><code>SSL_CLIENT_I_DN</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_ICN</code></td><td><code>SSL_CLIENT_I_DN_CN</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_IEMAIL</code></td><td><code>SSL_CLIENT_I_DN_Email</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_IO</code></td><td><code>SSL_CLIENT_I_DN_O</code></td><td>renombrada</td></tr>

<tr><td><code>SSL_CLIENT_IOU</code></td><td><code>SSL_CLIENT_I_DN_OU</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_IC</code></td><td><code>SSL_CLIENT_I_DN_C</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_ISP</code></td><td><code>SSL_CLIENT_I_DN_SP</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_CLIENT_IL</code></td><td><code>SSL_CLIENT_I_DN_L</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_EXPORT</code></td><td><code>SSL_CIPHER_EXPORT</code></td><td>renombrada</td></tr>

<tr><td><code>SSL_KEYSIZE</code></td><td><code>SSL_CIPHER_ALGKEYSIZE</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SECKEYSIZE</code></td><td><code>SSL_CIPHER_USEKEYSIZE</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_SSLEAY_VERSION</code></td><td><code>SSL_VERSION_LIBRARY</code></td><td>renombrada</td></tr>
<tr><td><code>SSL_STRONG_CRYPTO</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_SERVER_KEY_EXP</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>

<tr><td><code>SSL_SERVER_KEY_ALGORITHM</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_SERVER_KEY_SIZE</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_SERVER_SESSIONDIR</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_SERVER_CERTIFICATELOGDIR</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_SERVER_CERTFILE</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>

<tr><td><code>SSL_SERVER_KEYFILE</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_SERVER_KEYFILETYPE</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_CLIENT_KEY_EXP</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_CLIENT_KEY_ALGORITHM</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
<tr><td><code>SSL_CLIENT_KEY_SIZE</code></td><td><code>-</code></td><td>No soportado por mod_ssl</td></tr>
</table>
</section>
</section>

<section id="customlog"><title>Funciones Personalizadas de Log</title>
<p>
Cuando está habilitado el módulo <module>mod_ssl</module>, existen funciones adicionales
para el <a href="../mod/mod_log_config.html#formats">Formato de Log Personalizado</a> 
<module>mod_log_config</module> como se documenta en el capítulo referenciado. 
Junto con  la función de formato de eXtensión ``<code>%{</code><em>varname</em><code>}x</code>''
la cual puede ser usada para extender cualquier variable proporcionada por cualquier módulo,
una función criptográfica de formato adicional 
``<code>%{</code><em>name</em><code>}c</code>'' cryptography format function
exists for backward compatibility. The currently implemented function calls
are listed in <a href="#table3">Table 3</a>.</p>

<section id="table3">
<title>Table 3: Funciones criptográficas de Log Personalizado</title>
<table>
<columnspec><column width=".2"/><column width=".4"/></columnspec>
<tr><th>Llamada a la Función</th><th>Descripción</th></tr>

<tr><td><code>%...{version}c</code></td>   <td>SSL protocol version</td></tr>
<tr><td><code>%...{cipher}c</code></td>    <td>SSL cipher</td></tr>
<tr><td><code>%...{subjectdn}c</code></td> <td>Client Certificate Subject Distinguished Name</td></tr>
<tr><td><code>%...{issuerdn}c</code></td>  <td>Client Certificate Issuer Distinguished Name</td></tr>
<tr><td><code>%...{errcode}c</code></td>   <td>Certificate Verification Error (numerical)</td></tr>
<tr><td><code>%...{errstr}c</code></td>    <td>Certificate Verification Error (string)</td></tr>
</table>
</section>
</section>

</manualpage>