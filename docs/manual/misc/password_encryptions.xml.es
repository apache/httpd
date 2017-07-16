<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English revision: 1721975 -->
<!-- Spanish Translation: Daniel Ferradal <dferradal@apache.org> -->

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

<manualpage metafile="password_encryptions.xml.meta">
  <parentdocument href="./">Documentación diversa</parentdocument>

  <title>Formatos de contraseña</title>

  <summary>
    <p>Notas sobre los formatos de encriptación generados y comprendidos por Apache.</p>
  </summary>

  <section id="basic"><title>Autenticación Básica</title>

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

    <section><title>Generando valores con htpasswd</title>

      <example><title>bcrypt</title>
      $ htpasswd -nbB myName myPassword<br />
      myName:$2y$05$c4WoMPo3SXsafkva.HHa6uXQZWr7oboPiC2bT/r7q1BB8I2s0BRqC
      </example>

      <example><title>MD5</title>
      $ htpasswd -nbm myName myPassword<br />
      myName:$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/
      </example>

      <example><title>SHA1</title>
      $ htpasswd -nbs myName myPassword<br />
      myName:{SHA}VBPuJHI7uixaa6LQGWx4s+5GKNE=
      </example>

      <example><title>CRYPT</title>
      $ htpasswd -nbd myName myPassword<br />
      myName:rqXexS6ZhobKA
      </example>

    </section>

    <section>
      <title>Generando valores CRYPT y MD5 values con el programa de línea de comandos OpenSSL</title>

      <p>OpenSSL conoce el algoritmo MD5 específico-de-Apache.</p>

      <example><title>MD5</title>
      $ openssl passwd -apr1 myPassword<br />
      $apr1$qHDFfhPC$nITSVHgYbDAK1Y0acGRnY0
      </example>

      <example><title>CRYPT</title>
      openssl passwd -crypt myPassword<br />
      qQ5vTYO3c8dsU
      </example>
    </section>

    <section>
      <title>Validando contraseñas CRYPT o MD5 con el programa de línea de comandos OpenSSL</title>
      <p>El valor salt de una contraseña CRYPT es sus dos primeros caracteres 
      (convertidos a un valor binario). Para validar <code>myPassword</code> contra <code>rqXexS6ZhobKA</code></p>

      <example><title>CRYPT</title>
      $ openssl passwd -crypt -saltt rq myPassword<br />
      Warning: truncating password to 8 characters<br />
      rqXexS6ZhobKA
      </example>

      <p>Tenga en cuenta que usando <code>myPasswo</code> en lugar de
      <code>myPassword</code> producirá el mismo resultado porque solo se tienen en cuenta los 8 primeros caracteres de las contraseñas CRYPT.</p>

      <p>El valor salt para una contraseña MD5 está entre <code>$apr1$</code>
      y el siguiente <code>$</code> (como un valor binario codificado-en-Base64 máximo 8 caracteres).
      Para validar <code>myPassword</code> contra
      <code>$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/</code></p>

      <example><title>MD5</title>
      $ openssl passwd -apr1 -saltt r31..... myPassword<br />
      $apr1$r31.....$HqJZimcKQFAMYayBlzkrA/
      </example>
    </section>

    <section><title>Campos de contraseña de base de datos para mod_dbd</title>
      <p>La variante SHA1 es probablemente el formato más útil para autenticación DBD. Desde que las funciones SHA1 y Base64 están disponibles generalmente, otro software puede poblar una base de datos con contraseñas encriptadas que son utilizables con la autenticación básica de Apache.</p>

      <p>Para generar contraseñas de la variante Apache de SHA-1 para autenticación básica en varios lenguajes:</p>

      <example><title>PHP</title>
      '{SHA}' . base64_encode(sha1($password, TRUE))
      </example>

      <example><title>Java</title>
      "{SHA}" + new sun.misc.BASE64Encoder().encode(java.security.MessageDigest.getInstance("SHA1").digest(password.getBytes()))
      </example>

      <example><title>ColdFusion</title>
      "{SHA}" &amp; ToBase64(BinaryDecode(Hash(password, "SHA1"), "Hex"))
      </example>

      <example><title>Ruby</title>
      require 'digest/sha1'<br />
      require 'base64'<br />
      '{SHA}' + Base64.encode64(Digest::SHA1.digest(password))
      </example>

      <example><title>C or C++</title>
      Use la función APR: apr_sha1_base64
      </example>

      <example><title>Python</title>
      import base64<br />
      import hashlib<br />
      "{SHA}" + format(base64.b64encode(hashlib.sha1(password).digest()))
      </example>

      <example>
        <title>PostgreSQL (con las funciones contrib/pgcrypto instaladas)</title>
        '{SHA}'||encode(digest(password,'sha1'),'base64')
      </example>
    </section>

  </section>

  <section id="digest"><title>Autenticación Digest</title>
    <p>Apache reconoce un formato para las contraseñas de autenticación-digest - el MD5 hash de la cadena de caracteres <code>user:realm:password</code> como una cadena de 32-caracteres de dígitos hexadecimales. <code>realm</code> es el parámetro del Ámbito de Autorización para la directiva
    <directive module="mod_authn_core">AuthName</directive> en
    httpd.conf.</p>

    <section><title>Campos de contraseñaa de Base de datos para mod_dbd</title>

      <p>Puesto que la función MD5 está disponible generalmente, otro software puede rellenar la base de daatos con contraseñas encriptadas que son utilizables por la autenticación digest de Apache.</p>

      <p>Para generar contraseñas de autenticación-digest de Apache en varios lenguajes:</p>

      <example><title>PHP</title>
      md5($user . ':' . $realm . ':' .$password)
      </example>

      <example><title>Java</title>
      byte b[] = java.security.MessageDigest.getInstance("MD5").digest( (user + ":" + realm + ":" + password ).getBytes());<br />
      java.math.BigInteger bi = new java.math.BigInteger(1, b);<br />
      String s = bi.toString(16);<br />
      while (s.length() &lt; 32)<br />
      <indent>
        s = "0" + s;
      </indent>
      // La cadena s es la contraseña encriptada.
      </example>

      <example><title>ColdFusion</title>
      LCase(Hash( (user &amp; ":" &amp; realm &amp; ":" &amp; password) , "MD5"))
      </example>

      <example><title>Ruby</title>
      require 'digest/md5'<br />
      Digest::MD5.hexdigest(user + ':' + realm + ':' + password)
      </example>

      <example>
        <title>PostgreSQL (con las funciones contrib/pgcrypto instaladas)</title>
        encode(digest( user || ':' || realm || ':' || password , 'md5'), 'hex')
      </example>

    </section>
  </section>

</manualpage>
