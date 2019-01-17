<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1741841 -->
<!-- Spanish translation : Daniel Ferradal -->
<!-- Reviewed by Luis Joaquin Gil de Bernabé Pfeiffer -->
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

<manualpage metafile="htaccess.xml.meta">
<parentdocument href="./">How-To / Tutoriales</parentdocument>

<title>Tutorial del Servidor Apache HTTP: Ficheros .htaccess</title>

<summary>
    <p>Los ficheros <code>.htaccess</code> facilitan una forma de realizar 
    cambios en la configuración en contexto directorio.</p>
</summary>

<section id="related"><title>Ficheros .htaccess</title>
    <related>
        <modulelist>
            <module>core</module>
            <module>mod_authn_file</module>
            <module>mod_authz_groupfile</module>
            <module>mod_cgi</module>
            <module>mod_include</module>
            <module>mod_mime</module>
        </modulelist>

        <directivelist>
            <directive module="core">AccessFileName</directive>
            <directive module="core">AllowOverride</directive>
            <directive module="core">Options</directive>
            <directive module="mod_mime">AddHandler</directive>
            <directive module="core">SetHandler</directive>
            <directive module="mod_authn_core">AuthType</directive>
            <directive module="mod_authn_core">AuthName</directive>
            <directive module="mod_authn_file">AuthUserFile</directive>
            <directive module="mod_authz_groupfile">AuthGroupFile</directive>
            <directive module="mod_authz_core">Require</directive>
        </directivelist>

    </related>

    <note>Debería evitar usar ficheros <code>.htaccess</code> completamente si
    tiene acceso al fichero de configuración principal de httpd. Usar ficheros 
    <code>.htaccess</code> ralentiza su servidor Apache http. Cualquier 
    directiva que pueda incluir en un fichero <code>.htaccess</code> 
    estará mejor configurada dentro de una sección 
    <directive module="core">Directory</directive>, tendrá el mismo efecto y
    mejor rendimiento.</note>
</section>

<section id="what">
<title>Qué son/Cómo usarlos</title>

    <p>Los ficheros <code>.htaccess</code> (o "ficheros de configuración
    distribuida") facilitan una forma de realizar cambios en la configuración
    en contexto directorio. Un fichero, que contiene una o más directivas, se 
    coloca en un documento específico de un directorio, y estas directivas 
    aplican a ese directorio y todos sus subdirectorios.</p>

    <note><title>Nota:</title>
      <p>Si quiere llamar a su fichero <code>.htaccess</code> de otra manera, 
      puede cambiar el nombre del fichero usando la directiva <directive
      module="core">AccessFileName</directive>. Por ejemplo, si usted prefiere
      llamar al fichero <code>.config</code>, entonces puede poner lo siguiente
      en el fichero de configuración de su servidor:</p>

      <highlight language="config">
AccessFileName ".config"
      </highlight>
    </note>

    <p>Generalmente, los ficheros <code>.htaccess</code> usan la misma sintáxis 
    que los <a href="../configuring.html#syntax">ficheros de la configuración
    principal</a>. Lo que puede utilizar en estos ficheros lo determina la 
    directiva <directive module="core">AllowOverride</directive>. Esta directiva
    especifica, en categorías, qué directivas tendrán efecto si se encuentran en 
    un fichero <code>.htaccess</code>. Si se permite una directiva en un fichero 
    <code>.htaccess</code>, la documentación para esa directiva contendrá una 
    sección Override, especificando qué valor debe ir en 
    <directive module="core">AllowOverride</directive> para que se permita esa
    directiva.</p>

    <p>Por ejemplo, si busca en la documentación la directiva <directive
    module="core">AddDefaultCharset</directive>, encontrará que se permite en
    ficheros <code>.htaccess</code>. (Vea la línea de Contexto en el sumario de
    la directiva.) La línea <a
    href="../mod/directive-dict.html#Context">Override</a> muestra
    <code>FileInfo</code>. De este modo, debe tener al menos
    <code>AllowOverride FileInfo</code> para que esta directiva se aplique en
    ficheros <code>.htaccess</code>.</p>

    <example><title>Ejemplo:</title>
      <table>
        <tr>
          <td><a
          href="../mod/directive-dict.html#Context">Context:</a></td>
          <td>server config, virtual host, directory, .htaccess</td>
        </tr>

        <tr>
          <td><a
          href="../mod/directive-dict.html#Override">Override:</a></td>
          <td>FileInfo</td>
        </tr>
      </table>
    </example>

    <p>Si no está seguro de cuándo, una directiva en concreto, se puede usar en un 
    fichero <code>.htaccess</code>, consulte la documentación para esa directiva, 
    y compruebe la línea Context buscando ".htaccess".</p>
    </section>

    <section id="when"><title>Cuando (no) usar ficheros .htaccess</title>

    <p>Generalmente, solo debería usar ficheros <code>.htaccess</code> cuando no
    tiene acceso al fichero principal de configuración del servidor. Hay, por
    ejemplo, una creencia errónea de que la autenticación de usuario debería 
    hacerse siempre dentro de ficheros <code>.htaccess</code>, y, más recientemente, otra creencia errónea de que las directivas de 
    <module>mod_rewrite</module> deben ir en ficheros <code>.htaccess</code>. 
    Esto sencillamente no es el caso. Puede poner las configuraciones de 
    autenticación de usuario en la configuración principal del servidor, y esto 
    es de hecho, el método preferido de configurar Apache. Del mismo modo, las 
    directivas <code>mod_rewrite</code> funcionan mejor, en muchos sentidos, en 
    el fichero de configuración principal del servidor.</p>

    <p>Los ficheros <code>.htaccess</code> deberían usarse cuando su proveedor 
    de contenidos le permite hacer modificaciones de configuración 
    en contexto directorio, pero usted no tiene acceso de root en el servidor.
    En el caso de que el administrador no esté dispuesto a hacer cambios 
    frecuentes en la configuración, puede que sea necesario permitir a usuarios
    individuales realizar estos cambios de configuración en ficheros 
    <code>.htaccess</code> por ellos mismos. Lo cual ocurre a menudo, por 
    ejemplo, en casos donde los ISP están albergando múltiples sitios web de 
    usuario en una sola máquina, y quieren que sus usuarios tengan la 
    posibilidad de modificar sus configuraciones.</p>

    <p>Aun así, generalmente, el uso de ficheros <code>.htaccess</code> debería
    evitarse cuando sea posible. Cualquier configuración que consideraría poner
    en un fichero <code>.htaccess</code>, puede usarse con la misma efectividad
    en una sección <directive module="core"
    type="section">Directory</directive> en el fichero de configuración 
    del servidor.</p>

    <p>Hay dos razones para evitar el uso de ficheros <code>.htaccess</code>.</p>

    <p>La primera es el rendimiento. Cuando <directive
    module="core">AllowOverride</directive>
    está configurado para permitir el uso de ficheros <code>.htaccess</code>, 
    httpd buscará ficheros <code>.htaccess</code> en cada directorio. Así,
    permitiendo ficheros <code>.htaccess</code> provoca una pérdida de 
    rendimiento, ¡incluso aunque no los use! Además, los ficheros 
    <code>.htaccess</code> se cargan cada vez que se solicita un documento.</p>

    <p>Además tenga en cuenta que httpd debe buscar ficheros 
    <code>.htaccess</code> en todos los directorios de mayor jerarquía, 
    para poder terner la lista completa de directivas que debe aplicar. (Vea
    la sección sobre <a href="#how">Cómo se aplican las directivas</a>.) Así, si
    se solicita un fichero de un directorio <code>/www/htdocs/example</code>, 
    httpd debe buscar los siguientes ficheros:</p>

    <example>
      /.htaccess<br />
      /www/.htaccess<br />
      /www/htdocs/.htaccess<br />
      /www/htdocs/example/.htaccess
    </example>

    <p>De esta manera, por cada acceso a un fichero de ese directorio, hay 4 
    accesos adicionales al sistema de ficheros, incluso si ninguno de esos 
    ficheros está presente. (Tenga en cuenta que este caso solo se daría si los 
    ficheros <code>.htaccess</code> están activados en <code>/</code>, que 
    generalmente no es el caso.).</p>

    <p>En el caso de las directivas <directive
    module="mod_rewrite">RewriteRule</directive>, en el contexto de
    <code>.htaccess</code> estas expresiones regulares deben recompilarse con 
    cada solicitud a ese directorio, cuando en el contexto de configuración del
    servidor solo se compilan una vez y se cachean. Adicionalmente, las reglas
    en sí mismas son más complicadas, puesto que uno debe sortear las 
    restricciones que vienen acompañadas del contexto directorio y 
    <code>mod_rewrite</code>. Consulte la  <a
    href="../rewrite/intro.html#htaccess">Guía de Rewrite</a> para un mayor 
    detalle sobre este tema.</p>

    <p>La segunda consideración es de seguridad. Estará permitiendo que usuarios
    modifiquen la configuración del servidor, lo cual puede dar lugar a cambios sobre los que usted no tendrá ningún control. Medite profundamente si debe 
    dar a sus usuarios ese privilegio. Además tenga en cuenta que dar a los usuarios menos privilegios de los que necesitan dará lugar a más peticiones 
    de soporte. Asegúrese de que le indica a sus usuarios claramente el nivel de privilegios que les está dando. Especificando exactamente cómo ha 
    configurado <directive module="core">AllowOverride</directive>, e invíteles 
    a revisar la documentación relacionada, lo cual le ahorrará 
    bastantes confusiones más adelante.</p>

    <p>Tenga en cuenta que esto es equivalente por completo a poner un fichero
    <code>.htaccess</code> en un directorio <code>/www/htdocs/example</code> 
    con una directiva, y poner la misma directiva en una sección 
    Directory <code>&lt;Directory "/www/htdocs/example"&gt;</code> en su 
    configuración principal del servidor:</p>

    <p>Fichero <code>.htaccess</code> en <code>/www/htdocs/example</code>:</p>

    <example><title>Contenido de fichero .htaccess en
    <code>/www/htdocs/example</code></title>
    <highlight language="config">
AddType text/example ".exm"
    </highlight>
    </example>

    <example><title>Sección de su fichero <code>httpd.conf</code></title>
    <highlight language="config">
&lt;Directory "/www/htdocs/example"&gt;
    AddType text/example ".exm"
&lt;/Directory&gt;
    </highlight>
    </example>

    <p>Aun así, poniendo ésta en el fichero de configuración dará como resultado
    una menor pérdida de rendimiento, y como la configuración se carga una vez
    cuando el httpd arranca, en lugar de cada vez que se solicita un fichero.</p>

    <p>El uso de ficheros <code>.htaccess</code> puede desactivarse por completo
    configurando la directiva <directive module="core">AllowOverride</directive>
    a <code>none</code>:</p>

    <highlight language="config">
AllowOverride None
    </highlight>
</section>

<section id="how"><title>How directives are applied</title>

    <p>Las directivas de configuración que se encuentran en el fichero
    <code>.htaccess</code> se aplican al directorio en el que el fichero
    <code>.htaccess</code> se encuentra, y a todos sus subdirectorios. Sin 
    embargo, es importante recordar que puede haber otros ficheros 
    <code>.htaccess</code> en directorios previos. Las directivas se aplican en
    el orden en el que se encuentran. Por lo tanto, un fichero 
    <code>.htaccess</code> puede sobrescribir directivas que se encuentran
    en ficheros <code>.htaccess</code> que se encuentran en directorios previos 
    del árbol de directorios. Y estos, en cambio, pueden haber sobrescrito 
    directivas que se encontraban más arriba, o en el fichero principal de 
    configuración del servidor mismo.</p>

    <p>Ejemplo:</p>

    <p>En el directorio <code>/www/htdocs/example1</code> tenemos un fichero
    <code>.htaccess</code> que contiene lo siguiente:</p>

    <highlight language="config">
Options +ExecCGI
    </highlight>

    <p>(Nota: debe terner "<code>AllowOverride Options</code>" configurado para
    permitir el uso de la directiva "<directive
    module="core">Options</directive>" en ficheros 
    <code>.htaccess</code> files.)</p>

    <p>En el directorio <code>/www/htdocs/example1/example2</code> tenemos un
    fichero <code>.htaccess</code> que contiene:</p>

    <highlight language="config">
Options Includes
    </highlight>

    <p>Por este segundo fichero <code>.htaccess</code>, en el directorio
    <code>/www/htdocs/example1/example2</code>, la ejecución de CGI execution no
    está permitida, porque solo se ha definido <code>Options Includes</code>, 
    que sobrescribe completamente una configuración previa que se pudiera haber
    definido.</p>

    <section id="merge"><title>Incorporando el .htaccess en los ficheros de 
    configuración principal</title>

    <p>Como se ha comentado en la documentación en las <a
    href="../sections.html">Secciones de Configuración</a>, los ficheros
    <code>.htaccess</code> pueden sobrescribir las secciones <directive
    type="section" module="core">Directory</directive> por el directorio
    correspondiente, pero se sobrescribirán por otros tipos de secciones de 
    configuración de los ficheros de configuración principal. Este hecho se
    puede usar para forzar ciertas configuraciones, incluso en presencia
    de una configuración laxa de 
    <directive module="core">AllowOverride</directive>. Por ejemplo, para 
    prevenir la ejecución de un script mientras se permite cualquier otra cosa 
    en <code>.htaccess</code> puede usar:</p>

    <highlight language="config">
&lt;Directory "/www/htdocs"&gt;
    AllowOverride All
&lt;/Directory&gt;

&lt;Location "/"&gt;
    Options +IncludesNoExec -ExecCGI
&lt;/Location&gt;
    </highlight>

    <note>Este ejemplo asume que su <directive
    module="core">DocumentRoot</directive> es <code>/www/htdocs</code>.</note>
</section>

</section>

<section id="auth"><title>Ejemplo de Autenticación</title>

    <p>Si saltó directamente a esta parte del documento para averiguar como 
    hacer la autenticación, es important que tenga en cuenta una cosa. Hay una 
    creencia errónea de que necesita usar ficheros <code>.htaccess</code> para
    configurar autenticación con contraseña. Este no es el caso. Colocar las
    directivas de autenticación en una sección 
    <directive module="core" type="section">Directory</directive>, en su fichero
    de configuración principal, es el método recomendado para configurar esto, 
    y los ficheros <code>.htaccess</code> deberían usarse solamente si no tiene 
    acceso al fichero de configuración principal del servidor. Vea <a
    href="#when">más arriba</a> una explicación de cuando debería y cuando no
    debería usar ficheros <code>.htaccess</code>.</p>

    <p>Dicho esto, si todavía cree que debe usar el fichero
    <code>.htaccess</code>, podrá ver que una configuración como la que sigue 
    podría servirle.</p>

    <p>Contenido del fichero <code>.htaccess</code>:</p>

    <highlight language="config">
AuthType Basic
AuthName "Password Required"
AuthUserFile "/www/passwords/password.file"
AuthGroupFile "/www/passwords/group.file"
Require group admins
    </highlight>

    <p>Tenga en cuenta que <code>AllowOverride AuthConfig</code> debe estar
    habilitado para que estas directivas tengan algún efecto.</p>

    <p>Por favor vea el <a href="auth.html">tutorial de autenticación</a> para
    una explicación más completa de la autenticación y la autorización.</p>
</section>

<section id="ssi"><title>Ejemplo de Server Side Includes</title>

    <p>Otro uso común de ficheros <code>.htaccess</code> es activar Server Side 
    Includes para un directorio en particular. Esto puede hacerse 
    con las siguientes directivas de configuración, colocadas en un fichero
    <code>.htaccess</code> y el directorio deseado:</p>

    <highlight language="config">
Options +Includes
AddType text/html "shtml"
AddHandler server-parsed shtml
    </highlight>

    <p>Tenga en cuenta que <code>AllowOverride Options</code> y 
    <code>AllowOverride FileInfo</code> deben estar activadas para que estas 
    directivas tengan efecto.</p>

    <p>Por favor vea el <a href="ssi.html">tutorial de SSI</a> para una
    explicación más completa de server-side includes.</p>
</section>

<section id="rewrite"><title>Reglas de Rewrite en ficheros .htaccess</title>
    <p>Cuando use <directive module="mod_rewrite">RewriteRule</directive> en
    ficheros <code>.htaccess</code>, tenga en cuenta que el contexto 
    directorio cambia las cosas un poco. En concreto, las reglas son 
    relativas al directorio actual, en lugar de serlo de la petición de URI 
    solicitada originalmente.
    Considere los siguientes ejemplos:</p>

<highlight language="config">
# En httpd.conf
RewriteRule "^/images/(.+)\.jpg" "/images/$1.png"

# En .htaccess en el directorio raíz
RewriteRule "^images/(.+)\.jpg" "images/$1.png"

# En .htaccess en images/
RewriteRule "^(.+)\.jpg" "$1.png"
</highlight>

    <p>En un <code>.htaccess</code> en cualquier directorio del DocumentRoot, la 
    barra ("/") inicial se elimina del valor facilitado a <directive
    module="mod_rewrite">RewriteRule</directive>, y en el subdirectorio 
    <code>images</code>, se elimina <code>/images/</code> también de este valor. 
    Así, su expresión regular necesita omitir también esa parte.</p>

    <p>Consulte la <a href="../rewrite/">documentación de mod_rewrite</a> para 
    más detalles al usar <code>mod_rewrite</code>.</p>

</section>

<section id="cgi"><title>Ejemplo de CGI</title>

    <p>Finalmente, puede que quiera usar un fichero <code>.htaccess</code> para
    permitir la ejecución de programas CGI en un directorio en particular. Esto
    se puede implementar con la siguiente configuración:</p>

    <highlight language="config">
Options +ExecCGI
AddHandler cgi-script "cgi" "pl"
    </highlight>

    <p>Alternativamente, si quiere considerar como programas CGI todos los 
    ficheros de un directorio concreto, esto se puede conseguir con la siguiente 
    configuración:</p>

    <highlight language="config">
Options +ExecCGI
SetHandler cgi-script
    </highlight>

    <p>Tenga en cuenta que <code>AllowOverride Options</code> y 
    <code>AllowOverride FileInfo</code> deben estar ambas activadas para que 
    estas directivas tengan efecto.</p>

    <p>Por favor vea el <a href="cgi.html">tutorial CGI</a> para mayor detalle
    sobre programación y configuración de CGI.</p>

</section>

<section id="troubleshoot"><title>Resolución de problemas</title>

    <p>Cuando pone directivas en un fichero <code>.htaccess</code> y no obtiene 
    el efecto deseado hay una serie de cosas que pueden haber ido mal.</p>

    <p>El problema más común es que <directive module="core">AllowOverride
    </directive> no está configurada para que sus directivas puedan surtir
    efecto. Asegúrese de que no tiene <code>AllowOverride None</code> 
    configurado para el directorio en cuestión. Una buena forma de probar esto
    es poner "basura" en su fichero <code>.htaccess</code> y recargar la página. 
    Si no se genera un error en el servidor, casi seguro que tiene configurado 
    <code>AllowOverride None</code>.</p>

    <p>Si, por otro lado, obtiene errores de servidor al intentar acceder a 
    documentos, compruebe el log de errores de httpd. Seguramente le indiquen 
    que la directiva en uso en su fichero <code>.htaccess</code> no está 
    permitida.</p>

    <example>
    [Fri Sep 17 18:43:16 2010] [alert] [client 192.168.200.51] /var/www/html/.htaccess: DirectoryIndex not allowed here
    </example>

    <p>Esto indicará que o bien ha usado una directiva que no se permite nunca 
    en ficheros <code>.htaccess</code>, o que simplementa no tiene
    <directive module="core">AllowOverride</directive> configurado
    a un nivel suficiente para la directiva que ha usado. Consulte la
    documentación para esa directiva en particular para determinar cual es el 
    caso.</p>

    <p>Alternativamente, puede que le indique que hay un error de sintaxis en 
    el uso de la propia directiva.</p>

    <example>
    [Sat Aug 09 16:22:34 2008] [alert] [client 192.168.200.51] /var/www/html/.htaccess: RewriteCond: bad flag delimiters
    </example>

    <p>En este caso, el mensaje de error debería ser específico para el error de
    sintaxis concreto que ha cometido.</p>

</section>

</manualpage>
