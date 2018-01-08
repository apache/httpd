<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1738217 -->
<!-- Spanish Translation: Daniel Ferradal -->

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

<modulesynopsis metafile="mod_access_compat.xml.meta">

<name>mod_access_compat</name>
<description>Autorizaciones de grupo basadas en el host (nombre o dirección IP)</description>
<status>Extension</status>
<sourcefile>mod_access_compat.c</sourcefile>
<identifier>access_compat_module</identifier>
<compatibility>Disponible en el servidor Apache HTTP 2.3 como un módulo de compatibilidad con versiones previas de Apache http 2.x. Las directivas facilitadas por este módulo han quedado obsoletas en favor de la nueva refactorización de authz. Por favor vea <module>mod_authz_host</module></compatibility>

<summary>
    <p>Las directivas facilitadas por <module>mod_access_compat</module> se usan en las secciones 
    <directive module="core" type="section">Directory</directive>, 
    <directive module="core" type="section">Files</directive>, y 
    <directive module="core" type="section">Location</directive> así como en los ficheros 
    <code><a href="core.html#accessfilename">.htaccess</a></code> para controlar el acceso a partes específicas del servidor. El acceso se puede controlar en base al nombre de host del cliente, dirección IP u otras características de la petición del cliente, tal y como se capturan en las 
    <a href="../env.html">variables de entorno</a>. La directivas 
    <directive module="mod_access_compat">Allow</directive> y 
    <directive module="mod_access_compat">Deny</directive> se usan para especificar qué clientes tienen acceso y cuales no al servidor, mientras que la directiva 
    <directive module="mod_access_compat">Order</directive> configura el estado del acceso por defecto, y configura cómo las directivas 
    <directive module="mod_access_compat">Allow</directive> y 
    <directive module="mod_access_compat">Deny</directive> interactuan la una con la otra.</p>

    <p>Se pueden configurar simultáneamente restricciones basadas en el host y autenticación con contraseña. En ese caso, la directiva <directive module="mod_access_compat">Satisfy</directive> se usa para determinar como los dos sets de restricciones interactuan.</p>

    <note type="warning"><title>Atención</title>
      <p>Las directivas facilitadas por <module>mod_access_compat</module> han quedado obsoletas en favor de
      <module>mod_authz_host</module>. Mezclar directivas antiguas como 
      <directive module="mod_access_compat">Order</directive>, 
      <directive module="mod_access_compat">Allow</directive> o 
      <directive module="mod_access_compat">Deny</directive> con las nuevas directivas como 
      <directive module="mod_authz_core">Require</directive> es técnicamente posible pero no recomendable. Éste módulo se creó para dar soporte a configuraciones que solo contienen directivas antiguas para facilitar una actualización a la versión 2.4. Por favor compruebe la guía 
      <a href="../upgrading.html">Actualizando</a> para más información.</p>
    </note>

    <p>En general, las directivas de restricción de acceso aplican a todos los métodos de acceso (<code>GET</code>, <code>PUT</code>, <code>POST</code>, etc). Éste es el comportamiento deseado en la mayor parte de los casos. Sin embargo, es posible restringir algunos métodos, dejando otros métodos sin restricción, configurando las directivas dentro de una sección <directive module="core" type="section">Limit</directive>.</p>

    <note> <title>Fusionando secciones de configuración</title>
      <p>Cuando cualquier directiva facilitada por este módulo se usa en una nueva sección de configuración, no se heredará ninguna directiva facilitada por este módulo en secciones anteriores de configuración.</p>
    </note>

</summary>

<seealso><directive module="mod_authz_core">Require</directive></seealso>
<seealso><module>mod_authz_host</module></seealso>
<seealso><module>mod_authz_core</module></seealso>

<directivesynopsis>
<name>Allow</name>
<description>Controla qué hosts pueden acceder a un área del servidor</description>
<syntax> Allow from all|<var>host</var>|env=[!]<var>env-variable</var>
[<var>host</var>|env=[!]<var>env-variable</var>] ...</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>Limit</override>

<usage>
    <p>La directiva <directive>Allow</directive> afecta a qué hosts pueden acceder un área del servidor. El acceso puede controlarse por nombre de host, dirección IP, rango de direcciones IP, o por otras caracterísitcas de la petición del cliente capturadas en variables de entorno.</p>

    <p>El primer parámetro para esta directiva siempre es <code>from</code>. Los siguientes parámetros pueden tomar tres formas diferentes. Si se especifica <code>Allow from all</code>, entonces se permite el acceso a todos los host, dependiendo de la configuración de las directivas 
    <directive module="mod_access_compat">Deny</directive> y 
    <directive module="mod_access_compat">Order</directive> tal y como se indicó más arriba. Para permitir solo host específicos o grupos de host acceder al servidor, se puede especificar el <em>host</em> en cualquiera de los siguientes formatos:</p>

    <dl>
      <dt>Un nomre de dominio (parcial)</dt>

      <dd>
      <highlight language="config">
Allow from example.org
Allow from .net example.edu
      </highlight>
      
      <p>Hosts cuyo nombre coincide, o acaba en estas cadenas de caracteres se les permite acceso. Solo componentes completos pueden coincidir, así que el ejemplo de arriba coincidirá con <code>foo.example.org</code> pero no coincidirán con <code>fooexample.org</code>. Esta configuración provocará que Apache httpd haga una doble resolución de DNS en la dirección IP del cliente, independientemente de la configuración de la directiva 
      <directive module="core">HostnameLookups</directive>. Hará una resolución inversa de DNS en la dirección IP para encontrar el nombre de host asociado, y entonces hará una resolución del nombre de host para asegurarse de que coincide con la dirección IP original. Solo se le dará acceso al nombre de host si ambas resoluciones de DNS son consistentes.</p></dd>

      <dt>Una dirección IP completa</dt>

      <dd>
      <highlight language="config">
Allow from 10.1.2.3
Allow from 192.168.1.104 192.168.1.205
      </highlight>
      <p>Se le permite acceso a una dirección IP de un host</p></dd>

      <dt>Una dirección IP parcial</dt>

      <dd>
      <highlight language="config">
Allow from 10.1
Allow from 10 172.20 192.168.2
      </highlight>
      <p>Los primeros 1 al 3 bytes de una dirección IP, para restricción de subred.</p></dd>

      <dt>Una pareja de red/máscara de red</dt>

      <dd>
      <highlight language="config">
        Allow from 10.1.0.0/255.255.0.0
      </highlight>

      <p>Una red a.b.c.d, y una máscara de red w.x.y.z. Para una restricción de subred más específica.</p></dd>

      <dt>Una especificación de red/nnn CIDR</dt>

      <dd>
      <highlight language="config">
        Allow from 10.1.0.0/16
      </highlight>

      <p>Similar al caso anterior, exceptuando que la máscara de red se especifica con número de bits.</p></dd>
    </dl>

    <p>Tenga en cuenta que los tres últimos ejemplos coinciden exactamente con el mismo grupo de hosts.</p>

    <p>Direcciones y subredes IPv6 pueden especificarse como se describe aquí:</p>

    <highlight language="config">
Allow from 2001:db8::a00:20ff:fea7:ccea
Allow from 2001:db8::a00:20ff:fea7:ccea/10
    </highlight>

    <p>El tercer formato de parámetros para la directiva <directive>Allow</directive> permite que el acceso al servidor se controle mediante la existencia de 
    <a href="../env.html">variable de entorno</a>. Cuando se especifica 
    <code>Allow from env=<var>env-variable</var></code>, entonces se le da acceso si la variable de entorno <var>env-variable</var> existe. Cuando se especifica 
    <code>Allow from env=!<var>env-variable</var></code>, entonces se da acceso si la variable de entorno 
    <var>env-variable</var> no existe. El servidor facilita la configuración de variables de entorno de una manera flexible basándose en las características de la petición del cliente usando las directivas facilitadas por <module>mod_setenvif</module>. Por tanto, esta directiva se puede usar para permitir acceso basándose en tales factores como el <code>User-Agent</code> del cliente (tipo de navegador), <code>Referer</code>, u otros campos de cabeceras HTTP de petición.</p>

    <highlight language="config">
SetEnvIf User-Agent ^KnockKnock/2\.0 let_me_in
&lt;Directory "/docroot"&gt;
    Order Deny,Allow
    Deny from all
    Allow from env=let_me_in
&lt;/Directory&gt;
    </highlight>

    <p>En este caso, navegadores con una cadena user-agent que comienza con <code>KnockKnock/2.0</code> podrán acceder, y al resto se les denegará el acceso.</p>

    <note> <title>Fusión de secciones de configuración</title>
      <p>Cuando se usa cualquier directiva facilitada por este módulo en una nueva sección de configuración, no se heredará ninguna directiva facilitada por este módulo en secciones anteriores de configuración.</p>
    </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>Deny</name>
<description>Controla a qué hosts se les deniega el acceso al servidor</description>
<syntax> Deny from all|<var>host</var>|env=[!]<var>env-variable</var>
[<var>host</var>|env=[!]<var>env-variable</var>] ...</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>Limit</override>

<usage>
    <p>Esta directiva permite que se restrinja el acceso al servidor basándose en el nombre de host, dirección IP, o variables de entorno. Los parámetros para la directiva 
    <directive>Deny</directive> son idénticos a los parámetros para la directiva 
    <directive module="mod_access_compat">Allow</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Order</name>
<description>Controla el estado por defecto del acceso y el orden en que se evalúan 
  <directive>Allow</directive> y 
<directive>Deny</directive>.</description>
<syntax> Order <var>ordering</var></syntax>
<default>Order Deny,Allow</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>Limit</override>

<usage>

    <p>La directiva <directive>Order</directive> , junto con las directivas
    <directive module="mod_access_compat">Allow</directive> y
    <directive module="mod_access_compat">Deny</directive>, realizan un sistema de control de tres fases. La primera fase proceso o bien todas las directivas 
    <directive module="mod_access_compat">Allow</directive> o todas las directivas 
    <directive module="mod_access_compat">Deny</directive>, tal y como se haya especificado en la directiva  
    <directive module="mod_access_compat">Order</directive>. La segunda fase interpreta el resto de directivas 
    (<directive module="mod_access_compat">Deny</directive> o
    <directive module="mod_access_compat">Allow</directive>). La tercera fase se aplica a todas las peticiones que no coinciden con cualquiera de las dos fases anteriores.</p>

    <p>Tenga en cuenta que todas las directivas 
    <directive module="mod_access_compat">Allow</directive> y 
    <directive module="mod_access_compat">Deny</directive> son procesadas, al contrario que el cortafuegos típico, donde solo se usa la primera coincidencia. La última coincidencia es efectiva (también al contrario que un cortafuegos típico). Además, el orden en el que las directivas aparecen en la configuración no es relevante -- todas las líneas 
    <directive module="mod_access_compat">Allow</directive> se interpretan como un grupo, todas las líneas <directive module="mod_access_compat">Deny</directive> se interpretan como otro grupo, y el estado por defecto se procesa a sí mismo.</p>

    <p><em>Ordenar</em> es una de las dos:</p>

    <dl>
      <dt><code>Allow,Deny</code></dt>

      <dd>Primero, se interpretan todas las directivas <directive module="mod_access_compat">Allow</directive>; al menos una debe coincidir, o se deniega el acceso a la petición. Después, todas las directivas <directive module="mod_access_compat">Deny</directive> son interpretadas. Si alguna coincide, se deniega el acceso a la petición. Por último, cualquier petición que no encaje en una directiva <directive module="mod_access_compat">Allow</directive> o <directive module="mod_access_compat">Deny</directive> se les deniega el acceso por defecto.</dd>

      <dt><code>Deny,Allow</code></dt>

      <dd>Primero, se interpretan todas las directivas <directive module="mod_access_compat">Deny</directive>; si alguna coincide, se deniega el acceso a la petición <strong>a menos que</strong> también encaje con una directiva <directive module="mod_access_compat">Allow</directive>. Cualquier petición que no encaje ni con directivas <directive module="mod_access_compat">Allow</directive> ni <directive
      module="mod_access_compat">Deny</directive> se les permite el acceso.</dd>

      <dt><code>Mutual-failure</code></dt>

      <dd>Este orden tiene el mismo efecto que <code>Order Allow,Deny</code> y ha quedado obsoleto en su favor.</dd>
    </dl>

    <p>Las palabras clave solo pueden ser separadas por coma; no se permiten <em>espacios en blanco</em> entre ellas.</p>

    <table border="1">
      <tr>
        <th>Filtro</th>
        <th>Resultado Allow,Deny</th>
        <th>Resultado Deny,Allow</th>
      </tr><tr>
        <th>Solo coincide con Allow</th>
        <td>Petición permitida</td>
        <td>Petición permitida</td>
      </tr><tr>
        <th>Solo coincide con Deny</th>
        <td>Petición denegada</td>
        <td>Petición denegada</td>
      </tr><tr>
        <th>No coincide</th>
        <td>Por defecto con la segunda directiva: Denegado</td>
        <td>Por defecto con la segunda directiva: Permitido</td>
      </tr><tr>
        <th>Coincide con ambas Allow &amp; Deny</th>
        <td>Control de coincidencia final: Denegado</td>
        <td>Control de coincidencia final: Permitido</td>
      </tr>
    </table>

    <p>En el siguiente ejemplo, todos los host en el dominio example.org tienen permitido el acceso; el resto de host tienen el acceso denegado.</p>

    <highlight language="config">
Order Deny,Allow
Deny from all
Allow from example.org
    </highlight>

    <p>En el siguiente ejemplo, todos los hosts del dominio example.org tienen permitido el acceso, excepto para los host que están en el subdominio foo.example.org, a los que se le deniega el acceso. Todos los host que no coinciden con el dominio example.org tienen el acceso denegado porque el estado por defecto es <directive module="mod_access_compat">Deny</directive> con el acceso al servidor.</p>

    <highlight language="config">
Order Allow,Deny
Allow from example.org
Deny from foo.example.org
    </highlight>

    <p>Por otro lado, si el <directive>Order</directive> en el último ejemplo se cambia a <code>Deny,Allow</code>, se permitirá el acceso a todos los host. Esto pasa porque, independientemente del orden actual de las directivas en el fichero de configuración, <code>Allow from example.org</code> será interpretrado en último lugar y sobreescribirá la orden de <code>Deny from foo.example.org</code>. Todos los host que no estén en el dominio <code>example.org</code> también tendrán acceso porque el estado por defecto es <directive
    module="mod_access_compat">Allow</directive>.</p>

    <p>La presencia de una directiva <directive>Order</directive> puede afectar el acceso a una parte del servidor incluso en la ausencia de las directivas <directive module="mod_access_compat">Allow</directive>
    y <directive module="mod_access_compat">Deny</directive> por su efecto en el estado del acceso por defecto. Por ejemplo,</p>

    <highlight language="config">
&lt;Directory "/www"&gt;
    Order Allow,Deny
&lt;/Directory&gt;
    </highlight>

    <p>denegará todos los accesos al directorio <code>/www</code> porque el estado del acceso por defecto está configurado con <directive module="mod_access_compat">Deny</directive>.</p>

    <p>La directiva <directive>Order</directive> controla el orden de procesamiento de las directivas solo en cada fase del procesamiento de la configuración de un servidor. Esto implica, por ejemplo, que una directiva 
    <directive module="mod_access_compat">Allow</directive> o <directive
    module="mod_access_compat">Deny</directive> dentro de una sección
    <directive module="core" type="section">Location</directive> será siempre interpretada después de una directiva 
     <directive module="mod_access_compat">Allow</directive> o <directive
    module="mod_access_compat">Deny</directive> dentro de una sección
    <directive module="core" type="section">Directory</directive> o fichero <code>.htaccess</code>, independientemente de la configuración de la directiva <directive>Order</directive>. Para detalles sobre la fusión de secciones de configuración, vea la documentación en <a
    href="../sections.html">Cómo funcionan las secciones Directory, Location y Files</a>.</p>

    <note> <title>Fusión de secciones de configuración</title>
      <p>Cuando se usa cualquier directiva facilitada por este módulo en una nueva sección de configuración, no se heredará ninguna directiva facilitada por este módulo en secciones anteriores de configuración.</p>
    </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>Satisfy</name>
<description>Interacción entre control de acceso a nivel-de-hostess y autenticación de usuario</description>
<syntax>Satisfy Any|All</syntax>
<default>Satisfy All</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Política de acceso si se usan ambos <directive
    module="mod_access_compat">Allow</directive> y <directive
    module="mod_authz_core">Require</directive>. El parámetro puede ser <code>All</code> o <code>Any</code>. Esta directiva solo es útil si el acceso a un área en particular se está restringiendo por usuario/contraseña <em>y</em> dirección de host del cliente. En este caso el comportamiento por defecto (<code>All</code>) es requerir que el cliente pase la restricción de dirección de acceso <em>y</em> además introduce un usuario y contraseña válidos. Con la opción <code>Any</code> se le garantizará acceso al cliente si pasa la restricción de host o introduce un usuario y contraseña válidos. Esto puede usarse para restringir con contraseña el acceso a un area, pero para permitir acceso a los clientes desde unas direcciones en particular sin pedirles contraseña.</p>

    <p>Por ejemplo, si quisiera dejar entrar a personas de su red con acceso sin restricciones a una parte de su website, pero requiere que gente de fuera de su red facilite una contraseña, podría usar una configuración similar a la siguiente:</p>

    <highlight language="config">
Require valid-user
Allow from 192.168.1
Satisfy Any
    </highlight>

    <p>Otro uso típico de la directiva <directive>Satisfy</directive> es para suavizar las restricciones de acceso a un subdirectorio:</p>

    <highlight language="config">
&lt;Directory "/var/www/private"&gt;
    Require valid-user
&lt;/Directory&gt;

&lt;Directory "/var/www/private/public"&gt;
    Allow from all
    Satisfy Any
&lt;/Directory&gt;
    </highlight>

    <p>En el ejemplo de arriba, se requiere autenticación para el directorio <code>/var/www/private</code>, pero no se requerirá para el directorio <code>/var/www/private/public</code>.</p>

    <p>Desde la versión 2.0.51 las directivas <directive>Satisfy</directive> pueden restringirse a métodos específicos con secciones <directive module="core" type="section">Limit</directive> y <directive module="core" type="section"
    >LimitExcept</directive>.</p>

    <note> <title>Fusión de secciones de configuración.</title>
      <p>Cuando se usa cualquier directiva facilitada por este módulo en una nueva sección de configuración, no se heredará ninguna directiva facilitada por este módulo en secciones anteriores de configuración.</p>
    </note>

</usage>
   <seealso><directive module="mod_access_compat">Allow</directive></seealso>
   <seealso><directive module="mod_authz_core">Require</directive></seealso>
</directivesynopsis>

</modulesynopsis>
