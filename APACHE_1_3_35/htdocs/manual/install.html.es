<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<!-- translation 1.31 -->

<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <meta name="generator" content="HTML Tidy, see www.w3.org" />
    <meta http-equiv="Content-Type"
    content="text/html; charset=iso-8859-1" />

    <title>Compilaci&oacute;n e Instalaci&oacute;n de
    Apache</title>
  </head>
  <!-- Background white, links blue (unvisited), navy (visited), red (active) -->

  <body bgcolor="#FFFFFF" text="#000000" link="#0000FF"
  vlink="#000080" alink="#FF0000">
    <!--#include virtual="header.html" -->

    <h1 align="CENTER">Compilaci&oacute;n e Instalaci&oacute;n de
    Apache 1.3</h1>

    <p>Este documento cubre la compilaci&oacute;n e
    instalaci&oacute;n de Apache en sistemas Unix, usando el
    m&eacute;todo manual de construcci&oacute;n e
    instalaci&oacute;n. Si desea usar la interfaz estilo autoconf,
    deber&aacute; leer el fichero <code>INSTALL</code> en el
    directorio ra&iacute;z de la distribuci&oacute;n fuente de
    Apache. Para la compilaci&oacute;n e instalaci&oacute;n en
    plataformas espec&iacute;ficas, consulte</p>

    <ul>
      <li><a href="windows.html">Usar Apache con Microsoft
      Windows</a></li>

      <li><a href="cygwin.html">Usar Apache con Cygwin</a></li>

      <li><a href="netware.html">Usar Apache con Novell Netware
      5</a></li>

      <li><a href="mpeix.html">Usar Apache con HP MPE/iX</a></li>

      <li><a href="unixware.html">Compilaci&oacute;n de Apache bajo
      UnixWare</a></li>

      <li><a href="readme-tpf.html">Vistazo general de la
      versi&oacute;n TPF de Apache</a></li>
    </ul>

    <h2>Bajarse Apache</h2>

    <p>La informaci&oacute;n de la &uacute;ltima versi&oacute;n de
    Apache puede encontrarla en <a
    href="http://www.apache.org/">http://www.apache.org/</a>. En
    esta web podr&aacute; encontrar las versiones finales,
    versiones beta e informaci&oacute;n de sitios y r&eacute;plicas
    en la web y por ftp an&oacute;nimo.</p>

    <p>Si se ha bajado la distribuci&oacute;n binaria, vaya a <a
    href="#installing">Instalaci&oacute;n de Apache</a>. Si no es
    as&iacute; lea la siguiente secci&oacute;n como compilar el
    servidor.</p>

    <h2>Compilaci&oacute;n de Apache</h2>

    <p>La compilaci&oacute;n de Apache consiste en tres pasos.
    Primero seleccionar qu&eacute; <strong>m&oacute;dulos</strong>
    de Apache quiere incluir en el servidor. Segundo crear una
    configuraci&oacute;n para su sistema operativo. Tercero
    compilar el ejecutable.</p>

    <p>Toda la configuraci&oacute;n de Apache est&aacute; en el
    directorio <code>src</code> de la distribuci&oacute;n. Vaya al
    directorio <code>src</code>.</p>

    <ol>
      <li>
        <p>Seleccione m&oacute;dulos para compilar, en el fichero
        de <code>configuraci&oacute;n</code> de Apache. Descomente
        las l&iacute;neas correspondientes a los m&oacute;dulos
        opcionales que desee incluir (entre las l&iacute;neas
        <code>AddModule</code> al final del fichero), o escriba
        nuevas l&iacute;neas correspondientes a m&oacute;dulos
        adicionales que haya bajado o programado. (Vea <a
        href="misc/API.html">API.html</a> para ver la
        documentaci&oacute;n preliminar de c&oacute;mo escribir
        m&oacute;dulos Apache). Los usuarios avanzados pueden
        comentar los m&oacute;dulos por defecto si est&aacute;n
        seguros de que no los necesitan (tenga cuidado, ya que
        algunos de estos m&oacute;dulos son necesarios para el buen
        funcionamiento y una correcta seguridad del servidor).</p>

        <p>Deber&iacute;a leer tambi&eacute;n las instrucciones del
        fichero de <code>Configuraci&oacute;n</code> para comprobar
        si necesita configurar unas <code>l&iacute;neas</code> u
        otras.</p>
      </li>

      <li>
        <p>Configure Apache para su sistema operativo. Usted puede
        ejecutar un script como el mostrado m&aacute;s abajo.
        Aunque si esto falla o usted tiene alg&uacute;n
        requerimiento especial (<i>por ejemplo</i> incluir una
        librer&iacute;a adicional exigida por un m&oacute;dulo
        opcional) puede editarlo para utilizar en el fichero de
        <code>Configuraci&oacute;n</code> las siguientes opciones:
        <code>EXTRA_CFLAGS, LIBS, LDFLAGS,INCLUDES.</code></p>

        <p>Ejecute el script de
        <code>configuraci&oacute;n</code>:</p>

        <blockquote>
<pre>
    % Configure
    Using 'Configuration' as config file
     + configured for &lt;whatever&gt; platform
     + setting C compiler to &lt;whatever&gt; *
     + setting C compiler optimization-level to &lt;whatever&gt; *
     + Adding selected modules
     + doing sanity check on compiler and options
    Creating Makefile in support
    Creating Makefile in main
    Creating Makefile in os/unix
    Creating Makefile in modules/standard
</pre>
        </blockquote>

        <p>(*: Dependiendo de la configuraci&oacute;n y de su
        sistema. El resultado podr&iacute;a no coincidir con el
        mostrado; no hay problema).</p>

        <p>Esto genera un fichero <code>Makefile</code> a ser usado
        en el tercer paso. Tambi&eacute;n crea un
        <code>Makefile</code> en el directorio
        <code>support</code>, para la compilaci&oacute;n de
        programas de soporte.</p>

        <p>(Si quiere mantener varias configuraciones, puede
        indicarle a <code>Configure</code> una de las opciones en
        un fichero, como <code>Configure -fichero
        configuraci&oacute;n.ai</code>).</p>
      </li>

      <li>Escriba <code>make</code>.</li>
    </ol>

    <p>Los m&oacute;dulos de la distribuci&oacute;n de Apache son
    aquellos que hemos probado y utilizado regularmente varios
    miembros del grupo de desarrollo de Apache. Los m&oacute;dulos
    adicionales (creados por miembros del grupo o por terceras
    personas) para necesidades o funciones espec&iacute;ficas
    est&aacute;n disponibles en &lt;<a
    href="http://www.apache.org/dist/httpd/contrib/modules/">http://www.apache.org/dist/httpd/contrib/modules/</a>&gt;.
    Hay instrucciones en esa p&aacute;gina para a&ntilde;adir estos
    m&oacute;dulos en el n&uacute;cleo de Apache.</p>

    <h2><a id="installing" name="installing">Instalaci&oacute;n de
    Apache</a></h2>

    <p>Tendr&aacute; un fichero binario llamado <code>hhtpd</code>
    en el directorio <code>src</code>. Una distribuci&oacute;n
    binaria de Apache ya traer&aacute; este fichero.</p>

    <p>El pr&oacute;ximo paso es instalar el programa y
    configurarlo. Apache esta dise&ntilde;ado para ser configurado
    y ejecutado desde los directorios donde fue compilado. Si
    quiere ejecutarlo desde otro lugar, cree un directorio y copie
    los directorios <code>conf</code>, <code>logs</code> e
    <code>icons</code>. En cualquier caso deber&iacute;a leer las
    <a href="misc/security_tips.html#serverroot">sugerencias de
    seguridad</a> que describen c&oacute;mo poner los permisos del
    directorio ra&iacute;z.</p>

    <p>El paso siguiente es editar los ficheros de
    configuraci&oacute;n del servidor. Consiste en configurar
    varias <strong>directivas</strong> en los tres ficheros
    principales. Por defecto, estos ficheros est&aacute;n en el
    directorio <code>conf</code> y se llaman <code>srm.conf</code>,
    <code>access.conf</code> y <code>httpd.conf</code>. Para
    ayudarle a comenzar, hay ejemplos de estos ficheros en el
    directorio de la distribuci&oacute;n, llamados
    <code>srm.conf-dist</code>, <code>access.conf-dist</code> y
    <code>httpd.conf-dist</code>. Copie o renombre estos ficheros a
    los correspondientes nombres sin la terminaci&oacute;n
    <code>-dist</code>. Edite cada uno de ellos. Lea los
    comentarios cuidadosamente. Un error en la configuraci&oacute;n
    de estos ficheros podr&iacute;a provocar fallos en el servidor
    o volverlo inseguro. Tendr&aacute; tambi&eacute;n un fichero
    adicional en el directorio <code>conf</code> llamado
    <code>mime.conf</code>. Este fichero normalmente no tiene que
    ser editado.</p>

    <p>Primero edite el fichero <code>http.conf</code>. Este
    configura atributos generales del servidor: el n&uacute;mero de
    puerto, el usuario que lo ejecuta, <i>etc.</i> El siguiente a
    editar es <code>srm.conf</code>; este fichero configura la
    ra&iacute;z del &aacute;rbol de los documentos, funciones
    especiales como HTML analizado sint&aacute;cticamente por el
    servidor, mapa de imagen, <i>etc.</i> Finalmente, edite
    <code>access.conf</code> que configura los accesos.</p>

    <p>Adem&aacute;s de estos tres ficheros, el comportamiento del
    servidor puede ser modificado directorio a directorio usando
    los ficheros <code>.htaccess</code> para los directorios en los
    que acceda el servidor.</p>

    <h3>&iexcl;Configure el sistema de tiempo correctamente!</h3>

    <p>Una operaci&oacute;n de un servidor web requiere un tiempo
    concreto, ya que algunos elementos del protocolo HTTP se
    expresan en funci&oacute;n de la hora y el d&iacute;a. Por eso,
    es hora de investigar la configuraci&oacute;n de NTP o de otro
    sistema de sincronizaci&oacute;n de su Unix o lo que haga de
    equivalente en NT.</p>

    <h2>Programas de soporte para la compilaci&oacute;n</h2>

    <p>Adem&aacute;s del servidor principal <code>httpd</code> que
    se compila y configura como hemos visto, Apache incluye
    programas de soporte. Estos no son compilados por defecto. Los
    programas de soporte est&aacute;n en el directorio
    <code>support</code>. Para compilar esos programas, entre en el
    directorio indicado y ejecute el comando:</p>

    <blockquote>
<pre>
    make
</pre>
    </blockquote>
    <!--#include virtual="footer.html" -->
  </body>
</html>

