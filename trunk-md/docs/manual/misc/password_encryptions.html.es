<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="es" xml:lang="es"><head>
<meta content="text/html; charset=ISO-8859-1" http-equiv="Content-Type" />
<!--
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      -->
<title>Formatos de contraseña - Servidor HTTP Apache Versión 2.5</title>
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
<a href="http://www.apache.org/">Apache</a> &gt; <a href="http://httpd.apache.org/">Servidor HTTP</a> &gt; <a href="http://httpd.apache.org/docs/">Documentación</a> &gt; <a href="../">Versión 2.5</a> &gt; <a href="./">Documentación diversa</a></div><div id="page-content"><div id="preamble"><h1>Formatos de contraseña</h1>
<div class="toplang">
<p><span>Idiomas disponibles: </span><a href="../en/misc/password_encryptions.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/misc/password_encryptions.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/misc/password_encryptions.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a></p>
</div>

    <p>Notas sobre los formatos de encriptación generados y comprendidos por Apache.</p>
  </div>
<div id="quickview"><ul id="toc"><li><img alt="" src="../images/down.gif" /> <a href="#basic">Autenticación Básica</a></li>
<li><img alt="" src="../images/down.gif" /> <a href="#digest">Autenticación Digest</a></li>
</ul><h3>Consulte también</h3><ul class="seealso"><li><a href="#comments_section">Comentarios</a></li></ul></div>
<div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="basic" id="basic">Autenticación Básica</a></h2>

    <p>Hay cinco formatos que Apache reconoce para contraseñas de autenticación-básica. Tenga en cuenta que no todos los formatos funcionan en todas las plataformas:</p>

    <dl>
       <dt>bcrypt</dt>
       <dd>"$2y$" + el resultado del algoritmo crypt_blowfish.
       Vea el fichero código fuente de APR
       <a href="http://svn.apache.org/viewvc/apr/apr/trunk/crypto/crypt_blowfish.c?view=markup">crypt_blowfish.c</a>
       para más detalles sobre este algoritmo.</dd>

       <dt>MD5</dt>
       <dd>"$apr1$" + el resultado de un algoritmo específico-de-Apache usando una digest MD5 iterado (1.000 veces) de varias combinaciones aleatorias de un valor salt de 32-bit y la contraseña. Vea el fichero código fuente de APR
       <a href="http://svn.apache.org/viewvc/apr/apr/trunk/crypto/apr_md5.c?view=markup">apr_md5.c</a>
       para más detalles sobre este algoritmo.</dd>

       <dt>SHA1</dt>
       <dd>"{SHA}" + digest SHA1 codificado-en-Base64 de la contraseña. Inseguro.</dd>

       <dt>CRYPT</dt>
       <dd>Solo Unix. Usa la función tradicional de Unix <code>crypt(3)</code> con un valor salt de 32-bit generado aleatoriamente (solo se usan 12 bits) y los primeros 8 caracteres de la contraseña. Inseguro.</dd>

       <dt>PLAIN TEXT (texto plano) (i.e. <em>sin encriptar</em>)</dt>
       <dd>Solo Windows &amp; Netware. Inseguro.</dd>
    </dl>

    <h3>Generando valores con htpasswd</h3>

      <div class="example"><h3>bcrypt</h3><p><code>
      $ htpasswd -nbB myName myPassword<br />
      myName:$2y$05$c4WoMPo3SXsafkva.HHa6uXQZWr7oboPiC2bT/r7q1BB8I2s0BRqC
      </code></p></div>

      <div class="example"><h3>MD5</h3><p><code>
      $ htpasswd -nbm myName myPassword<br />
      myName:$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/
      </code></p></div>

      <div class="example"><h3>SHA1</h3><p><code>
      $ htpasswd -nbs myName myPassword<br />
      myName:{SHA}VBPuJHI7uixaa6LQGWx4s+5GKNE=
      </code></p></div>

      <div class="example"><h3>CRYPT</h3><p><code>
      $ htpasswd -nbd myName myPassword<br />
      myName:rqXexS6ZhobKA
      </code></p></div>

    

    <h3>Generando valores CRYPT y MD5 values con el programa de línea de comandos OpenSSL</h3>
      

      <p>OpenSSL conoce el algoritmo MD5 específico-de-Apache.</p>

      <div class="example"><h3>MD5</h3><p><code>
      $ openssl passwd -apr1 myPassword<br />
      $apr1$qHDFfhPC$nITSVHgYbDAK1Y0acGRnY0
      </code></p></div>

      <div class="example"><h3>CRYPT</h3><p><code>
      openssl passwd -crypt myPassword<br />
      qQ5vTYO3c8dsU
      </code></p></div>
    

    <h3>Validando contraseñas CRYPT o MD5 con el programa de línea de comandos OpenSSL</h3>
      
      <p>El valor salt de una contraseña CRYPT es sus dos primeros caracteres 
      (convertidos a un valor binario). Para validar <code>myPassword</code> contra <code>rqXexS6ZhobKA</code></p>

      <div class="example"><h3>CRYPT</h3><p><code>
      $ openssl passwd -crypt -saltt rq myPassword<br />
      Warning: truncating password to 8 characters<br />
      rqXexS6ZhobKA
      </code></p></div>

      <p>Tenga en cuenta que usando <code>myPasswo</code> en lugar de
      <code>myPassword</code> producirá el mismo resultado porque solo se tienen en cuenta los 8 primeros caracteres de las contraseñas CRYPT.</p>

      <p>El valor salt para una contraseña MD5 está entre <code>$apr1$</code>
      y el siguiente <code>$</code> (como un valor binario codificado-en-Base64 máximo 8 caracteres).
      Para validar <code>myPassword</code> contra
      <code>$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/</code></p>

      <div class="example"><h3>MD5</h3><p><code>
      $ openssl passwd -apr1 -saltt r31..... myPassword<br />
      $apr1$r31.....$HqJZimcKQFAMYayBlzkrA/
      </code></p></div>
    

    <h3>Campos de contraseña de base de datos para mod_dbd</h3>
      <p>La variante SHA1 es probablemente el formato más útil para autenticación DBD. Desde que las funciones SHA1 y Base64 están disponibles generalmente, otro software puede poblar una base de datos con contraseñas encriptadas que son utilizables con la autenticación básica de Apache.</p>

      <p>Para generar contraseñas de la variante Apache de SHA-1 para autenticación básica en varios lenguajes:</p>

      <div class="example"><h3>PHP</h3><p><code>
      '{SHA}' . base64_encode(sha1($password, TRUE))
      </code></p></div>

      <div class="example"><h3>Java</h3><p><code>
      "{SHA}" + new sun.misc.BASE64Encoder().encode(java.security.MessageDigest.getInstance("SHA1").digest(password.getBytes()))
      </code></p></div>

      <div class="example"><h3>ColdFusion</h3><p><code>
      "{SHA}" &amp; ToBase64(BinaryDecode(Hash(password, "SHA1"), "Hex"))
      </code></p></div>

      <div class="example"><h3>Ruby</h3><p><code>
      require 'digest/sha1'<br />
      require 'base64'<br />
      '{SHA}' + Base64.encode64(Digest::SHA1.digest(password))
      </code></p></div>

      <div class="example"><h3>C or C++</h3><p><code>
      Use la función APR: apr_sha1_base64
      </code></p></div>

      <div class="example"><h3>Python</h3><p><code>
      import base64<br />
      import hashlib<br />
      "{SHA}" + format(base64.b64encode(hashlib.sha1(password).digest()))
      </code></p></div>

      <div class="example"><h3>PostgreSQL (con las funciones contrib/pgcrypto instaladas)</h3><p><code>
        
        '{SHA}'||encode(digest(password,'sha1'),'base64')
      </code></p></div>
    

  </div><div class="top"><a href="#page-header"><img alt="top" src="../images/up.gif" /></a></div>
<div class="section">
<h2><a name="digest" id="digest">Autenticación Digest</a></h2>
    <p>Apache reconoce un formato para las contraseñas de autenticación-digest - el MD5 hash de la cadena de caracteres <code>user:realm:password</code> como una cadena de 32-caracteres de dígitos hexadecimales. <code>realm</code> es el parámetro del Ámbito de Autorización para la directiva
    <code class="directive"><a href="../mod/mod_authn_core.html#authname">AuthName</a></code> en
    httpd.conf.</p>

    <h3>Campos de contraseñaa de Base de datos para mod_dbd</h3>

      <p>Puesto que la función MD5 está disponible generalmente, otro software puede rellenar la base de daatos con contraseñas encriptadas que son utilizables por la autenticación digest de Apache.</p>

      <p>Para generar contraseñas de autenticación-digest de Apache en varios lenguajes:</p>

      <div class="example"><h3>PHP</h3><p><code>
      md5($user . ':' . $realm . ':' .$password)
      </code></p></div>

      <div class="example"><h3>Java</h3><p><code>
      byte b[] = java.security.MessageDigest.getInstance("MD5").digest( (user + ":" + realm + ":" + password ).getBytes());<br />
      java.math.BigInteger bi = new java.math.BigInteger(1, b);<br />
      String s = bi.toString(16);<br />
      while (s.length() &lt; 32)<br />
      <span class="indent">
        s = "0" + s;
      </span>
      // La cadena s es la contraseña encriptada.
      </code></p></div>

      <div class="example"><h3>ColdFusion</h3><p><code>
      LCase(Hash( (user &amp; ":" &amp; realm &amp; ":" &amp; password) , "MD5"))
      </code></p></div>

      <div class="example"><h3>Ruby</h3><p><code>
      require 'digest/md5'<br />
      Digest::MD5.hexdigest(user + ':' + realm + ':' + password)
      </code></p></div>

      <div class="example"><h3>PostgreSQL (con las funciones contrib/pgcrypto instaladas)</h3><p><code>
        
        encode(digest( user || ':' || realm || ':' || password , 'md5'), 'hex')
      </code></p></div>

    
  </div></div>
<div class="bottomlang">
<p><span>Idiomas disponibles: </span><a href="../en/misc/password_encryptions.html" hreflang="en" rel="alternate" title="English">&nbsp;en&nbsp;</a> |
<a href="../es/misc/password_encryptions.html" title="Español">&nbsp;es&nbsp;</a> |
<a href="../fr/misc/password_encryptions.html" hreflang="fr" rel="alternate" title="Français">&nbsp;fr&nbsp;</a></p>
</div><div class="top"><a href="#page-header"><img src="../images/up.gif" alt="top" /></a></div><div class="section"><h2><a id="comments_section" name="comments_section">Comentarios</a></h2><div class="warning"><strong>Notice:</strong><br />This is not a Q&amp;A section. Comments placed here should be pointed towards suggestions on improving the documentation or server, and may be removed again by our moderators if they are either implemented or considered invalid/off-topic. Questions on how to manage the Apache HTTP Server should be directed at either our IRC channel, #httpd, on Freenode, or sent to our <a href="http://httpd.apache.org/lists.html">mailing lists</a>.</div>
<script type="text/javascript"><!--//--><![CDATA[//><!--
var comments_shortname = 'httpd';
var comments_identifier = 'http://httpd.apache.org/docs/trunk/misc/password_encryptions.html';
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