<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1875083 -->
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

<modulesynopsis metafile="mod_usertrack.xml.meta">
<name>mod_usertrack</name>
<description>
Registro de tipo <em>clickstream</em> de la actividad del usuario en un sitio
</description>
<status>Extension</status>
<sourcefile>mod_usertrack.c</sourcefile>
<identifier>usertrack_module</identifier>

<summary>
    <p>Proporciona un seguimiento del usuario a través de su sitio web mediante
    cookies del navegador.</p>
</summary>


<section id="logging">
<title>Registro</title>

    <p><module>mod_usertrack</module> establece una cookie que puede registrarse
    mediante los formatos de registro configurables de <module>mod_log_config</module>:</p>

    <highlight language="config">
LogFormat "%{Apache}n %r %t" usertrack
CustomLog "logs/clickstream.log" usertrack
    </highlight>

</section>

<directivesynopsis>
<name>CookieDomain</name>
<description>El dominio al que se aplica la cookie de seguimiento</description>
<syntax>CookieDomain <em>domain</em></syntax>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>

    <p>Esta directiva controla el establecimiento del dominio al que
    se aplica la cookie de seguimiento. Si no está presente, no se
    incluye ningún dominio en el campo de cabecera de la cookie.</p>

    <p>La cadena de dominio <strong>debe</strong> comenzar con un punto, y
    <strong>debe</strong> incluir al menos un punto incrustado. Es decir,
    <code>.example.com</code> es válido, pero <code>www.example.com</code> y
    <code>.com</code> no lo son.</p>

    <note>La mayoría de los navegadores en uso actualmente no permiten establecer
    cookies para un dominio de nivel superior de dos partes, como
    <code>.co.uk</code>, aunque tal dominio aparentemente cumple los requisitos
    anteriores.<br />

    Estos dominios son equivalentes a dominios de nivel superior como
    <code>.com</code>, y permitir tales cookies puede ser un riesgo de
    seguridad. Por lo tanto, si está bajo un dominio de nivel superior de dos
    partes, debería seguir usando su dominio real, como lo haría con cualquier
    otro dominio de nivel superior (por ejemplo <code>.example.co.uk</code>).
    </note>

    <highlight language="config">
    CookieDomain .example.com
    </highlight>
</usage>
</directivesynopsis>


<directivesynopsis>
<name>CookieExpires</name>
<description>Tiempo de caducidad de la cookie de seguimiento</description>
<syntax>CookieExpires <em>expiry-period</em></syntax>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>Cuando se usa, esta directiva establece un tiempo de caducidad en la
    cookie generada por el módulo usertrack. El <em>expiry-period</em>
    puede indicarse como un número de segundos, o en un formato como
    "2 weeks 3 days 7 hours". Las denominaciones válidas son:
    years, months, weeks, days, hours, minutes y seconds. Si el tiempo
    de caducidad se expresa en cualquier formato que no sea un único número
    que indique el número de segundos, debe ir entre comillas dobles.</p>

    <p>Si no se usa esta directiva, las cookies solo duran la
    sesión actual del navegador.</p>

    <highlight language="config">
    CookieExpires "3 weeks"
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CookieName</name>
<description>Nombre de la cookie de seguimiento</description>
<syntax>CookieName <em>token</em></syntax>
<default>CookieName Apache</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>Esta directiva le permite cambiar el nombre de la cookie que usa este
    módulo con fines de seguimiento. Por defecto la cookie se llama
    "<code>Apache</code>".</p>

    <p>Debe especificar un nombre de cookie válido; los resultados son
    impredecibles si usa un nombre que contenga caracteres inusuales.
    Los caracteres válidos incluyen A-Z, a-z, 0-9, "_" y "-".</p>

    <highlight language="config">
    CookieName clicktrack
    </highlight>
</usage>

</directivesynopsis>

<directivesynopsis>
<name>CookieStyle</name>
<description>Formato del campo de cabecera de la cookie</description>
<syntax>CookieStyle
    Netscape|Cookie|Cookie2|RFC2109|RFC2965</syntax>
<default>CookieStyle Netscape</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>Esta directiva controla el formato del campo de cabecera de la
    cookie. Los tres formatos permitidos son:</p>

    <ul>
      <li><strong>Netscape</strong>, que es la sintaxis original, ahora obsoleta.
      Esta es la opción por defecto, y la sintaxis que Apache ha usado
      históricamente.</li>

      <li><strong>Cookie</strong> o <strong>RFC2109</strong>, que es la sintaxis que
      sustituyó a la sintaxis Netscape.</li>

      <li><strong>Cookie2</strong> o <strong>RFC2965</strong>, que es la sintaxis
      de cookies más reciente.</li>
    </ul>

    <p>No todos los clientes pueden entender todos estos formatos, pero
    debería usar el más reciente que sea generalmente aceptable para los
    navegadores de sus usuarios. En el momento de escribir esto, la mayoría de
    los navegadores admiten los tres formatos, siendo <code>Cookie2</code>
    el formato preferido.</p>

    <highlight language="config">
    CookieStyle Cookie2
    </highlight>
</usage>
</directivesynopsis>



<directivesynopsis>
<name>CookieTracking</name>
<description>Activa la cookie de seguimiento</description>
<syntax>CookieTracking on|off</syntax>
<default>CookieTracking off</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>Cuando <module>mod_usertrack</module> está cargado, y se establece
    <code>CookieTracking on</code>, Apache enviará una cookie de seguimiento
    de usuario para todas las peticiones nuevas. Esta directiva puede
    usarse para activar o desactivar este comportamiento a nivel de
    servidor o de directorio. Por defecto, activar
    <module>mod_usertrack</module> <strong>no</strong>
    activará las cookies. </p>

    <highlight language="config">
    CookieTracking on
    </highlight>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CookieSecure</name>
<description>Añade el atributo 'Secure' a la cookie</description>
<syntax>CookieSecure on|off</syntax>
<default>CookieSecure off</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>2.5.1 y posteriores</compatibility>

<usage>
    <p>Cuando se establece a 'ON', se añade el atributo de cookie 'Secure' a la
    cookie de seguimiento de este módulo. Este atributo indica a los navegadores
    que transmitan la cookie únicamente por HTTPS.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CookieHTTPOnly</name>
<description>Añade el atributo 'HTTPOnly' a la cookie</description>
<syntax>CookieHTTPOnly on|off</syntax>
<default>CookieHTTPOnly off</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>2.5.1 y posteriores</compatibility>

<usage>
    <p>Cuando se establece a 'ON', se añade el atributo de cookie 'HTTPOnly' a la
    cookie de seguimiento de este módulo. Este atributo indica a los navegadores
    que impidan que javascript lea el valor de la cookie.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CookieSameSite</name>
<description>Añade el atributo 'SameSite' a la cookie</description>
<syntax>CookieSameSite None|Lax|Strict</syntax>
<default>unset</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>
<compatibility>2.5.1 y posteriores</compatibility>

<usage>
    <p>Cuando se establece a 'None', 'Lax', o 'Strict', se añade el atributo de
    cookie 'SameSite' a la cookie de seguimiento de este módulo con el valor
    correspondiente. Este atributo indica al navegador cómo tratar la cookie
    cuando se solicita en un contexto entre sitios (cross-site).</p>

     <note type="Warning">
        <p>Un valor de 'None' establece 'SameSite=None', que es la configuración
        más permisiva. Para omitir este atributo, omita la directiva por completo.</p>
    </note>

</usage>
</directivesynopsis>

</modulesynopsis>
