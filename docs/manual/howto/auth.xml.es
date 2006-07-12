<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 151405:421174 (outdated) -->

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

<manualpage metafile="auth.xml.meta">
<parentdocument href="./">How-To / Tutoriales</parentdocument>

<title>Autentificaci&#243;n, Autorizaci&#243;n y Control de Acceso</title>

<summary>
    <p>La autentificaci&#243;n es cualquier proceso mediante el cual se
    verifica que alguien es quien dice ser. La autorizaci&#243;n es
    cualquier proceso por el cual a alguien se le permite estar donde
    quiere ir, o tener la informaci&#243;n que quiere tener.</p>
</summary>
  
<section id="related"><title>M&#243;dulos y Directivas relacionadas</title>
    <related>
      <modulelist>
        <module>mod_auth</module>
        <module>mod_access</module>
      </modulelist>

      <directivelist>
        <directive module="mod_access">Allow</directive>
        <directive module="mod_auth">AuthGroupFile</directive>
        <directive module="core">AuthName</directive>
        <directive module="core">AuthType</directive>
        <directive module="mod_auth">AuthUserFile</directive>
        <directive module="mod_access">Deny</directive>
        <directive module="core">Options</directive>
        <directive module="core">Require</directive>
      </directivelist>
    </related>
</section>

<section id="introduction"><title>Introducci&#243;n</title>
    <p>Si en su sitio web tiene informaci&#243;n sensible o dirigida
    s&#243;lo a un peque&#241;o grupo de personas, las t&#233;cnicas
    explicadas en &#233;ste art&#237;culo le ayudar&#225;n a
    asegurarse de que las personas que ven esas p&#225;ginas son las
    personas que usted quiere que las vean.</p>

    <p>Este art&#237;culo cubre la manera "est&#225;ndar" de proteger
    partes de su sitio web que la mayor&#237;a de ustedes van a usar.</p>
</section>

<section id="theprerequisites"><title>Los Prerrequisitos</title>
    <p>Las directivas tratadas en &#233;ste art&#237;culo necesitar&#225;n
    ir en el archivo de configuraci&#243;n principal de su servidor
    (t&#237;picamente en una secci&#243;n del tipo
    <directive module="core" type="section">Directory</directive>),
    o en archivos de configuraci&#243;n por directorios (archivos 
    <code>.htaccess</code>).</p>

    <p>Si planea usar archivos <code>.htaccess</code>, necesitar&#225;
    tener una configuraci&#243;n en el servidor que permita poner directivas
    de autentificaci&#243;n en estos archivos. Esto se logra con la
    directiva <directive module="core">AllowOverride</directive>,
    la cual especifica cu&#225;les directivas, en caso de existir, pueden
    ser colocadas en los archivos de configuraci&#243;n por directorios.</p>

    <p>Ya que se est&#225; hablando de autentificaci&#243;n, necesitar&#225;
    una directiva <directive module="core">AllowOverride</directive> como
    la siguiente:</p>

    <example>
      AllowOverride AuthConfig
    </example>

    <p>O, si s&#243;lo va a colocar directivas directamente en el principal
    archivo de configuraci&#243;n del servidor, por supuesto necesitar&#225;
    tener permiso de escritura a ese archivo.</p>

    <p>Y necesitar&#225; saber un poco acerca de la estructura de
    directorios de su servidor, con la finalidad de que sepa d&#243;nde
    est&#225;n algunos archivos. Esto no deber&#237;a ser muy
    dif&#237;cil, y tratar&#233; de hacerlo sencillo cuando lleguemos a
    ese punto.</p>
</section>

<section id="gettingitworking"><title>Puesta en funcionamiento</title>
    <p>Aqu&#237; est&#225; lo esencial en cuanto a proteger con
    contrase&#241;a un directorio de su servidor.</p>

    <p>Necesitar&#225; crear un archivo de contrase&#241;as. &#201;ste
    archivo deber&#237;a colocarlo en alg&#250;n sitio no accesible
    mediante la Web. Por ejemplo, si sus documentos son servidos desde
    <code>/usr/local/apache/htdocs</code> usted podr&#237;a querer colocar
    el(los) archivo(s) de contrase&#241;as en
    <code>/usr/local/apache/passwd</code>.</p>

    <p>Para crear un archivo de contrase&#241;as, use la utilidad
    <program>htpasswd</program> que viene con Apache.
    &#201;sta utilidad puede encontrarla en el directorio <code>bin</code>
    de cualquier sitio en que haya instalado Apache. Para crear el
    archivo, escriba:</p>

    <example>
      htpasswd -c /usr/local/apache/passwd/passwords rbowen
    </example>

    <p><program>htpasswd</program> le pedir&#225; la contrase&#241;a, y luego se
    la volver&#225; a pedir para confirmarla:</p>

    <example>
      # htpasswd -c /usr/local/apache/passwd/passwords rbowen<br />
      New password: mypassword<br />
      Re-type new password: mypassword<br />
      Adding password for user rbowen
    </example>

    <p>Si <program>htpasswd</program> no est&#225; en su ruta, por supuesto
    tendr&#225; que escribir la ruta completa al archivo para ejecutarlo.
    En mi servidor, &#233;ste archivo est&#225; en
    <code>/usr/local/apache/bin/htpasswd</code></p>

    <p>El siguiente paso es configurar el servidor para que solicite una
    contrase&#241;a y decirle al servidor a qu&#233; usuarios se les
    permite el acceso. Puede hacer esto editando el archivo
    <code>httpd.conf</code> o usando un archivo <code>.htaccess</code>.
    Por ejemplo, si desea proteger el directorio
    <code>/usr/local/apache/htdocs/secret</code>, puede usar las siguientes
    directivas, ya sea coloc&#225;ndolas en el archivo
    <code>/usr/local/apache/htdocs/secret/.htaccess</code>,
    o en <code>httpd.conf</code> dentro de una secci&#243;n &lt;Directory
    /usr/local/apache/apache/htdocs/secret&gt;.</p>

    <example>
      AuthType Basic<br />
      AuthName "Restricted Files"<br />
      AuthUserFile /usr/local/apache/passwd/passwords<br />
      Require user rbowen
    </example>

    <p>Vamos a examinar cada una de estas directivas por separado. La
    directiva <directive module="core">AuthType</directive> selecciona
    el m&#233;todo que se va a usar para autentificar al usuario. El
    m&#233;todo m&#225;s com&#250;n es <code>Basic</code>, y &#233;ste
    m&#233;todo est&#225; implementado en <module>mod_auth</module>. Es importante
    ser consciente, sin embargo, de que la autentificaci&#243;n B&#225;sica
    env&#237;a la contrase&#241;a desde el cliente hasta el navegador sin
    encriptar. Por lo tanto, este m&#233;todo no deber&#237;a ser usado
    para informaci&#243;n altamente sensible. Apache soporta otro m&#233;todo
    de autentificaci&#243;n: <code>AuthType Digest</code>. Este m&#233;todo
    est&#225; implementado en <module>mod_auth_digest</module> y es mucho m&#225;s
    seguro. S&#243;lo las versiones m&#225;s recientes de clientes soportan
    la autentificaci&#243;n del tipo Digest.</p>

    <p>La directiva <directive module="core">AuthName</directive> establece
    el <dfn>Dominio (Realm)</dfn> a usar en la
    autentificaci&#243;n. El dominio (realm) cumple
    dos funciones importantes. Primero, el cliente frecuentemente presenta
    esta informaci&#243;n al usuario como parte del cuatro de di&#225;logo
    para la contrase&#241;a. Segundo, es usado por el cliente para determinar 
    qu&#233; contrase&#241;a enviar para un &#225;rea autentificada dada.</p>

    <p>As&#237;, por ejemplo, una vez que el cliente se haya autentificado en
    el &#225;rea <code>"Restricted Files"</code>,
    autom&#225;ticamente se volver&#225; a tratar de usar la misma
    contrase&#241;a en cualquier &#225;rea del mismo servidor que est&#233;
    marcado con el Dominio (Realm) <code>"Restricted Files"</code>. Por lo tanto,
    puede evitar que se le pida al usuario la contrase&#241;a
    m&#225;s de una vez permitiendo compartir el mismo dominio (realm)
    para m&#250;ltiples &#225;reas restringidas. Por supuesto, por
    razones de seguridad, el cliente siempre necesitar&#225; pedir de
    nuevo la contrase&#241;a cuando cambie el nombre de la
    m&#225;quina del servidor.</p>

    <p>La directiva <directive module="mod_auth">AuthUserFile</directive>
    establece la ruta al archivo de contrase&#241;a que acabamos de crear
    con <program>htpasswd</program>. Si tiene un gran n&#250;mero de usuarios,
    ser&#237;a bastante lento buscar por medio de un archivo en texto plano
    para autentificar al usuario en cada solicitud. Apache tambi&#233;n tiene
    la capacidad de almacenar la informaci&#243;n del usuario en 
    archivos r&#225;pidos de bases de datos. El m&#243;dulo <module>mod_auth_dbm</module>
    proporciona la directiva <directive
    module="mod_auth_dbm">AuthDBMUserFile</directive>. Estos archivos pueden
    ser creados y manipulados con el programa
    <program>dbmmanage</program>. Muchos otros tipos
    de opciones de autentificaci&#243;n est&#225;n disponibles en m&#243;dulos
    de terceras partes en la <a href="http://modules.apache.org/">Base de
    datos de M&#243;dulos de Apache</a>.</p>

    <p>Finalmente, la directiva <directive module="core">Require</directive>
    proporciona la parte de la autorizaci&#243;n del proceso estableciendo
    el usuario al que se le permite acceder a ese &#225;rea del servidor.
    En la pr&#243;xima secci&#243;n, discutimos varias formas de usar la
    directiva <directive module="core">Require</directive>.</p>
</section>

<section id="lettingmorethanonepersonin"><title>Permitir el acceso a m&#225;s
de una persona</title>
    <p>Las directivas anteriores s&#243;lo permiten que una persona
    (espec&#237;ficamente alguien con un nombre de usuario de
    <code>rbowen</code>) acceda al directorio. En la mayor&#237;a de los
    casos, usted querr&#225; permitir el acceso a m&#225;s de una persona.
    Aqu&#237; es donde entra la directiva <directive module="mod_auth"
    >AuthGroupFile</directive>.</p>

    <p>Si desea permitir la entrada a m&#225;s de una persona, necesitar&#225;
    crear un archivo de grupo que asocie nombres de grupo con una lista
    de usuarios perteneciente a ese grupo. El formato de este archivo es muy sencillo,
    y puede crearlo con su editor favorito. El contenido del archivo
    ser&#225; parecido a este:</p>

   <example>
     GroupName: rbowen dpitts sungo rshersey
   </example>

    <p>Esto es solo una lista de miembros del grupo escritos en una 
    l&#237;nea separados por espacios.</p>

    <p>Para agregar un usuario a un archivo de contrase&#241;as ya existente,
    escriba:</p>

    <example>
      htpasswd /usr/local/apache/passwd/passwords dpitts
    </example>

    <p>Obtendr&#225; la misma respuesta que antes, pero el nuevo usuario ser&#225; agregado
    al archivo existente, en lugar de crear un nuevo archivo.
    (Es la opci&#243;n <code>-c</code> la que se cree un nuevo archivo
    de contrase&#241;as).</p>

    <p>Ahora, necesita modificar su archivo <code>.htaccess</code> para que
    sea como el siguiente:</p>

    <example>
      AuthType Basic<br />
      AuthName "By Invitation Only"<br />
      AuthUserFile /usr/local/apache/passwd/passwords<br />
      AuthGroupFile /usr/local/apache/passwd/groups<br />
      Require group GroupName
    </example>

    <p>Ahora, cualquiera que est&#233; listado en el grupo <code>GroupName</code>,
    y figure en el archivo <code>password</code>, se le permitir&#225;
    el acceso, si escribe la contrase&#241;a correcta.</p>

    <p>Existe otra manera de permitir entrar a m&#250;ltiples usuarios que
    es menos espec&#237;fica. En lugar de crear un archivo de grupo, puede
    usar s&#243;lo la siguiente directiva:</p>

    <example>
      Require valid-user
    </example>

    <p>Usando eso en vez de la l&#237;nea <code>Require user rbowen</code>,
    le permitir&#225; el acceso a cualquiera que est&#233; listado en el
    archivo de contrase&#241;as y que haya introducido correctamente su
    contrase&#241;a. Incluso puede emular el comportamiento del grupo
    aqu&#237;, s&#243;lo manteniendo un archivo de contrase&#241;a para
    cada grupo. La ventaja de esta t&#233;cnica es que Apache s&#243;lo
    tiene que verificar un archivo, en vez de dos. La desventaja es que
    usted tiene que mantener un grupo de archivos de contrase&#241;a, y
    recordar referirse al correcto en la directiva <directive
    module="mod_auth">AuthUserFile</directive>.</p>
</section>

<section id="possibleproblems"><title>Posibles Problemas</title>
    <p>Por la manera en la que la autentificaci&#243;n b&#225;sica est&#225;
    especificada, su nombre de usuario y contrase&#241;a debe ser verificado
    cada vez que se solicita un documento del servidor. Incluso si est&#225;
    recargando la misma p&#225;gina, y por cada imagen de la p&#225;gina
    (si vienen de un directorio protegido). Como se puede imaginar, esto
    retrasa un poco las cosas. El retraso es proporcional al
    tama&#241;o del archivo de contrase&#241;a, porque se tiene que abrir ese
    archivo, y recorrer la lista de usuarios hasta que encuentre su nombre.
    Y eso se tiene que hacer cada vez que se cargue la p&#225;gina.</p>

    <p>Una consecuencia de esto es que hay un l&#237;mite pr&#225;ctico
    de cu&#225;ntos usuarios puede colocar en un archivo de contrase&#241;as.
    Este l&#237;mite variar&#225; dependiendo del rendimiento de su equipo
    servidor en particular, pero puede esperar observar una disminuci&#243;n
    una vez que inserte unos cientos de entradas, y puede que entonces considere
    un m&#233;todo distinto de autentificaci&#234;n.</p>
</section>

<section id="whatotherneatstuffcanido"><title>&#191;Qu&#233; otra cosa
sencilla y efectiva puedo hacer?</title>
    <p>La autentificaci&#243;n por nombre de usuario y contrase&#241;a es
    s&#243;lo parte del cuento. Frecuentemente se desea permitir el acceso
    a los usuarios basandose en algo m&#225;s que qui&#233;nes son. Algo como de
    d&#243;nde vienen.</p>

    <p>Las directivas <directive module="mod_access">Allow</directive> y
    <directive module="mod_access">Deny</directive> posibilitan permitir
    y rechazar el acceso dependiendo del nombre o la direcci&#243;n de la
    m&#225;quina que solicita un documento. La directiva <directive
    module="mod_access">Order</directive> va de la mano con estas dos, y le
    dice a Apache en qu&#233; orden aplicar los filtros.</p>

    <p>El uso de estas directivas es:</p>

    <example>
      Allow from <var>address</var>
    </example>

    <p>donde <var>address</var> es una direcci&#243;n IP (o una
    direcci&#243;n IP parcial) o un nombre de dominio completamente
    cualificado (o un nombre de dominio parcial); puede proporcionar
    m&#250;ltiples direcciones o nombres de dominio, si lo desea.</p>

    <p>Por ejemplo, si usted tiene a alguien que manda mensajes no deseados
    a su foro, y quiere que no vuelva a acceder, podr&#237;a hacer lo
    siguiente:</p>

    <example>
      Deny from 205.252.46.165
    </example>

    <p>Los visitantes que vengan de esa direcci&#243;n no podr&#225;n
    ver el contenido afectado por esta directiva. Si, por el
    contrario, usted tiene un nombre de m&#225;quina pero no una
    direcci&#243;n IP, tambi&#233;n puede usarlo.</p>

    <example>
      Deny from <var>host.example.com</var>
    </example>

    <p>Y, si le gustar&#237;a bloquear el acceso de un dominio entero,
    puede especificar s&#243;lo parte de una direcci&#243;n o nombre de
    dominio:</p>

    <example>
      Deny from <var>192.101.205</var><br />
      Deny from <var>cyberthugs.com</var> <var>moreidiots.com</var><br />
      Deny from ke
    </example>

    <p>Usar <directive module="mod_access">Order</directive> le permitir&#225;
    estar seguro de que efectivamente est&#225; restringiendo el acceso
    al grupo al que quiere permitir el acceso, combinando una directiva
    <directive module="mod_access">Deny</directive> y una <directive
    module="mod_access">Allow</directive>:</p>

    <example>
      Order deny,allow<br />
      Deny from all<br />
      Allow from <var>dev.example.com</var>
    </example>

    <p>Usando s&#243;lo la directiva <directive
    module="mod_access">Allow</directive> no har&#237;a lo que desea, porque
    le permitir&#237;a entrar a la gente proveniente de esa m&#225;quina, y
    adicionalmente a cualquier persona. Lo que usted quiere es dejar entrar
    <em>s&#243;lo</em> aquellos.</p>
</section>

<section id="moreinformation"><title>M&#225;s informaci&#243;n</title>
    <p>Tambi&#233;n deber&#237;a leer la documentaci&#243;n de
    <module>mod_auth</module> y <module>mod_access</module> que
    contiene m&#225;s informaci&#243;n acerca de c&#243;mo funciona todo esto.</p>
</section>
</manualpage>


