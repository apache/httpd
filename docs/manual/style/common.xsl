<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/TR/xhtml1/strict">

  <!--                                                          -->
  <!-- Please, don't hard-code output strings! Use the language -->
  <!-- files and the translation "stuff"...                     -->
  <!--                                                          -->

 <!-- Constants used for case translation -->
 <xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'" />
 <xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

 <xsl:variable name="path">
 <xsl:choose>
 <xsl:when test="*/relative-path/@href">
     <xsl:value-of select="*/relative-path/@href"/>
 </xsl:when>
 <xsl:otherwise>
  <xsl:value-of select="'..'"/>
 </xsl:otherwise>
 </xsl:choose>
 </xsl:variable>

  <!--                              -->
  <!-- Builds the moduleindex page  -->
  <!--                              -->
  <xsl:template match="moduleindex">
    <html>
      <head>
        <title>
          <xsl:value-of select="title"/><xsl:value-of select="$messages/message[@name='apachetitle']"/>
        </title>
        <link rel="stylesheet" type="text/css" href="../style/manual.css" />
      </head>
      <body>
        <blockquote>
          <div align="center">
            <img src="../images/sub.gif">
            <xsl:attribute name="alt"><xsl:value-of select="$messages/message[@name='apachedocalt']"/></xsl:attribute></img>
            <h3><xsl:value-of select="$messages/message[@name='apachehttpserver']"/></h3>
          </div>
          <h1 align="center"><xsl:value-of select="title"/></h1>
          <xsl:apply-templates select="summary" />
          <h2><xsl:value-of select="$messages/message[@name='corefeatures']"/></h2>
          <dl>
            <xsl:for-each select="document(modulefilelist/modulefile)/modulesynopsis">
              <xsl:sort select="name"/>
              <xsl:if test="status='MPM' or status='Core'">
                <dt><a href="{name}.html"><xsl:value-of select="name"/></a></dt>
                <dd><xsl:apply-templates select="description"/></dd>
              </xsl:if>
            </xsl:for-each>
          </dl>
          <h2><xsl:value-of select="$messages/message[@name='othermodules']"/></h2>
          <dl>
            <xsl:for-each select="document(modulefilelist/modulefile)/modulesynopsis">
              <xsl:sort select="name"/>
              <xsl:if test="status!='MPM' and status!='Core'">
                <dt><a href="{name}.html"><xsl:value-of select="name"/></a></dt>
                <dd><xsl:apply-templates select="description"/></dd>
              </xsl:if>
            </xsl:for-each>
          </dl>
        </blockquote>
        <!-- Page footer -->
        <hr />
        <h3 align="center"><xsl:value-of select="$messages/message[@name='apachehttpserver']"/></h3>
        <a href="./"><img src="../images/index.gif"><xsl:attribute name="alt"><xsl:value-of select="$messages/message[@name='index']"/></xsl:attribute></img></a>
        <a href="../"><img src="../images/home.gif"><xsl:attribute name="alt"><xsl:value-of select="$messages/message[@name='home']"/></xsl:attribute></img></a>
      </body>
    </html>
  </xsl:template> <!-- /moduleindex -->

  <!--                                                    -->
  <!-- <directiveindex>                                   -->
  <!-- Builds the directive index page                    -->
  <!--                                                    -->
  <xsl:template match="directiveindex">
    <html>
      <head>
        <title>
          <xsl:value-of select="title"/><xsl:value-of select="$messages/message[@name='apachetitle']"/>
        </title>
        <link rel="stylesheet" type="text/css" href="../style/manual.css" />
      </head>
      <body>
        <blockquote>
          <div align="center">
            <img src="../images/sub.gif">
            <xsl:attribute name="alt"><xsl:value-of select="$messages/message[@name='apachedocalt']"/></xsl:attribute></img>
            <h3><xsl:value-of select="$messages/message[@name='apachehttpserver']"/></h3>
          </div>
          <h1 align="center"><xsl:value-of select="title"/></h1>
          <xsl:apply-templates select="summary" />
          <ul>
            <xsl:for-each select="document(modulefilelist/modulefile)/modulesynopsis/directivesynopsis">
              <xsl:sort select="name"/>
              <xsl:if test="not(@location)">
                <li><a href="{/modulesynopsis/name}.html#{translate(name,$uppercase,$lowercase)}"><xsl:value-of select="name"/></a></li>
              </xsl:if>
            </xsl:for-each>
          </ul>
        </blockquote>
        <!-- Page footer -->
        <hr />
        <h3 align="center"><xsl:value-of select="$messages/message[@name='apachehttpserver']"/></h3>
        <a href="./"><img src="../images/index.gif"><xsl:attribute name="alt"><xsl:value-of select="$messages/message[@name='index']"/></xsl:attribute></img></a>
        <a href="../"><img src="../images/home.gif"><xsl:attribute name="alt"><xsl:value-of select="$messages/message[@name='home']"/></xsl:attribute></img></a>
      </body>
    </html>
  </xsl:template> <!-- /directiveindex -->

  <!--                                                    -->
  <!-- <manualpage>                                       -->
  <!-- Process an entire document into an HTML page       -->
  <!--                                                    -->
  <xsl:template match="manualpage">
    <html>
      <head>
        <xsl:comment> 
          XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
                This file is generated from xml source: DO NOT EDIT
          XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        </xsl:comment>
        <title>
          <xsl:value-of select="title"/><xsl:value-of
          select="$messages/message[@name='apachetitle']"/>
        </title>
        <link rel="stylesheet" type="text/css"
        href="{$path}/style/manual.css" />
     </head>
     <body>
        <blockquote>
          <div align="center">
            <img src="{$path}/images/sub.gif">
            <xsl:attribute name="alt"><xsl:value-of
            select="$messages/message[@name='apachedocalt']"/></xsl:attribute></img>
            <h3><xsl:value-of
            select="$messages/message[@name='apachehttpserver']"/></h3>
          </div>
          <h1 align="center"><xsl:value-of select="title"/></h1>

          <xsl:apply-templates select="summary"/>
          
          <ul>
	  <xsl:apply-templates select="section" mode="index"/>
          </ul>

          <hr/>
          <xsl:apply-templates select="section"/>
       </blockquote>
        <!-- Page footer -->
        <h3 align="center"><xsl:value-of
        select="$messages/message[@name='apachehttpserver']"/></h3>
        <a href="./"><img src="{$path}/images/index.gif"><xsl:attribute
        name="alt"><xsl:value-of
        select="$messages/message[@name='index']"/></xsl:attribute></img></a>
        <a href="{$path}/"><img src="{$path}/images/home.gif"><xsl:attribute
        name="alt"><xsl:value-of
        select="$messages/message[@name='home']"/></xsl:attribute></img></a>
      </body>
    </html>
  </xsl:template><!-- /manualpage -->
  

  <!--                                                    -->
  <!-- <modulesynopsis>                                   -->
  <!-- Process an entire document into an HTML page       -->
  <!--                                                    -->
  <xsl:template match="modulesynopsis">
    <html>
      <head>
        <xsl:comment> 
          XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
                This file is generated from xml source: DO NOT EDIT
          XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        </xsl:comment>
        <title>
          <xsl:value-of select="name"/><xsl:value-of select="$messages/message[@name='apachetitle']"/>
        </title>
        <link rel="stylesheet" type="text/css" href="../style/manual.css" />
      </head>
      <body>
        <blockquote>
          <div align="center">
            <img src="../images/sub.gif">
            <xsl:attribute name="alt"><xsl:value-of select="$messages/message[@name='apachedocalt']"/></xsl:attribute></img>
            <h3><xsl:value-of select="$messages/message[@name='apachehttpserver']"/></h3>
          </div>
          <h1 align="center"><xsl:value-of select="$messages/message[@name='apachemodule']"/><xsl:text> </xsl:text> <xsl:value-of select="name"/></h1>
          <!-- Description and module-headers -->
          <table bgcolor="#cccccc" cellpadding="0" cellspacing="1"><tr><td>
            <table bgcolor="#ffffff">
              <tr>
                <td valign="top" nowrap="nowrap"><span class="help"><xsl:value-of select="$messages/message[@name='description']"/>:</span></td>
                <td><xsl:apply-templates select="description"/></td>
              </tr>
              <tr>
                <td nowrap="nowrap"><a class="help" href="module-dict.html#Status"><xsl:value-of select="$messages/message[@name='status']"/>:</a></td>
                <td><xsl:value-of select="status"/></td>
              </tr>
              <xsl:if test="identifier">
                <tr>
                  <td nowrap="nowrap"><a class="help" href="module-dict.html#ModuleIdentifier"><xsl:value-of select="$messages/message[@name='moduleidentifier']"/>:</a> </td>
                  <td><xsl:value-of select="identifier"/></td>
                </tr>
              </xsl:if>
              <xsl:if test="compatibility">
                <tr>
                  <td valign="top" align="left"><a class="help" href="module-dict.html#Compatibility"><xsl:value-of select="$messages/message[@name='compatibility']"/>:</a> </td>
                  <td><xsl:apply-templates select="compatibility"/></td>
                </tr>
              </xsl:if>
            </table>
          </td></tr></table>
   
          <!-- Summary of module features/usage (1 to 3 paragraphs, optional) -->
   
          <xsl:if test="summary">
            <h2><xsl:value-of select="$messages/message[@name='summary']"/></h2>
            <xsl:apply-templates select="summary"/>
          </xsl:if>
   
          <!-- Index of directives, automatically generated from
          directivesynopsis/name -->
          <h2><xsl:value-of
          select="$messages/message[@name='directives']"/></h2>
          <xsl:if test="directivesynopsis">
            <ul>
              <xsl:for-each select="directivesynopsis">
                <xsl:sort select="name"/>
                <xsl:variable name="name"><xsl:value-of
                select="name"/></xsl:variable>
                <xsl:variable name="lowername"
                select="translate($name, $uppercase, $lowercase)" />
                <xsl:if test="not(@location)">
                  <li><a href="#{$lowername}"><xsl:value-of
                  select="name"/></a></li>
                </xsl:if>
                <xsl:if test="./@location">
                  <xsl:variable name="location"><xsl:value-of
                  select="./@location"/></xsl:variable>
                  <xsl:variable name="lowerlocation"
                  select="translate($location, $uppercase,
                  $lowercase)" />
                  <li><a
                  href="{$lowerlocation}.html#{$lowername}"><xsl:value-of
                  select="name"/></a></li>
                </xsl:if>
              </xsl:for-each>
            </ul>
          </xsl:if>
          <xsl:if test="not(directivesynopsis)">
            <p><xsl:value-of
            select="$messages/message[@name='nodirectives']"/></p>
          </xsl:if>
   
          <xsl:if test="seealso">
            <p><strong><xsl:value-of
            select="$messages/message[@name='seealso']"/></strong></p>
            <ul>
              <xsl:for-each select="seealso">
                <li><xsl:apply-templates/></li>
              </xsl:for-each>
            </ul>
          </xsl:if>
   
          <!-- Sections of documentation about the module as a whole -->
          <xsl:apply-templates select="section"/>
          <hr />
   
          <!-- Directive documentation -->
          <xsl:apply-templates select="directivesynopsis">
            <xsl:sort select="name"/>
          </xsl:apply-templates> 
   
        </blockquote>
        <!-- Page footer -->
        <h3 align="center"><xsl:value-of select="$messages/message[@name='apachehttpserver']"/></h3>
        <a href="./"><img src="../images/index.gif"><xsl:attribute name="alt"><xsl:value-of select="$messages/message[@name='index']"/></xsl:attribute></img></a>
        <a href="../"><img src="../images/home.gif"><xsl:attribute name="alt"><xsl:value-of select="$messages/message[@name='home']"/></xsl:attribute></img></a>
      </body>
    </html>
  </xsl:template><!-- /modulesynopsis -->
  
  
  <!-- Subsections: get a lower level heading -->
    <xsl:template match="section/section">
     <xsl:variable name="href">
        <xsl:value-of select="@id"/>
      </xsl:variable>
        <!-- Section heading -->
      <xsl:if test="@id">
        <h3><a name="{$href}"><xsl:apply-templates select="./title" mode="print"/></a></h3>
      </xsl:if>
      <xsl:if test="not(@id)">
        <h3><xsl:apply-templates select="./title" mode="print"/></h3>
      </xsl:if>
        <!-- Section body -->
          <xsl:apply-templates/>
    </xsl:template>
  
  <!-- Process a documentation section -->
    <xsl:template match="section">
      <xsl:variable name="href">
        <xsl:value-of select="@id"/>
      </xsl:variable>
        <!-- Section heading -->
      <xsl:if test="@id">
        <h2><a name="{$href}"><xsl:apply-templates select="./title" mode="print"/></a></h2>
      </xsl:if>
      <xsl:if test="not(@id)">
        <h2><xsl:apply-templates select="./title" mode="print"/></h2>
      </xsl:if>
        <!-- Section body -->
          <xsl:apply-templates/>
    </xsl:template>
  
    <xsl:template match="section/title" mode="print">
      <xsl:apply-templates/>
    </xsl:template>
  
    <!-- Don't print the title twice -->
    <xsl:template match="section/title"></xsl:template>

    <xsl:template match="section" mode="index">
      <xsl:variable name="href">
        <xsl:value-of select="@id"/>
      </xsl:variable>
      <li><a href="#{$href}"><xsl:apply-templates select="title"
      mode="print"/></a>
        <xsl:if test="section">
          <ul><xsl:apply-templates select="section" mode="index"/></ul>
        </xsl:if>
      </li>
    </xsl:template>

  
  <xsl:template match="directivesynopsis">

  <xsl:if test="not(@location)">
  <xsl:variable name="name">
    <xsl:value-of select="./name"/>
  </xsl:variable>
  <xsl:variable name="lowername" 
     select="translate($name, $uppercase, $lowercase)" />
  <!-- Directive heading gets both mixed case and lowercase anchors,
       and includes lt/gt only for "section" directives -->
  <h2><a name="{$name}"><xsl:if test="./@type='section'">&lt;</xsl:if
      ><xsl:value-of select="./name"/><xsl:if test="./@type='section'"
      >&gt;</xsl:if></a><xsl:text> </xsl:text><a 
      name="{$lowername}"><xsl:value-of select="$messages/message[@name='directive']"/></a></h2>

<!-- Directive header -->
<table bgcolor="#cccccc" border="0" cellspacing="0" cellpadding="1">
<tr><td>
<table bgcolor="#ffffff">
  <tr>
    <td nowrap="nowrap"><strong><xsl:value-of select="$messages/message[@name='description']"/>: </strong></td>
    <td><xsl:value-of select="description"/></td>
  </tr>
  <tr>
    <td nowrap="nowrap"><a class="help" href="directive-dict.html#Syntax"><xsl:value-of select="$messages/message[@name='syntax']"/>:</a> </td>
    <td><xsl:apply-templates select="syntax"/></td>
  </tr>
  <xsl:if test="default">
    <tr>
      <td nowrap="nowrap"><a class="help" href="directive-dict.html#Default"><xsl:value-of select="$messages/message[@name='default']"/>:</a> </td>
      <td><code><xsl:value-of select="default"/></code></td>
    </tr>
    </xsl:if>
      <tr>
        <td nowrap="nowrap"><a class="help" href="directive-dict.html#Context"><xsl:value-of select="$messages/message[@name='context']"/>:</a> </td>
        <td><xsl:apply-templates select="contextlist"/></td>
      </tr>
      <xsl:if test="override">
        <tr>
          <td nowrap="nowrap"><a class="help" href="directive-dict.html#Override"><xsl:value-of select="$messages/message[@name='override']"/>:</a> </td>
          <td><xsl:value-of select="override"/></td>
        </tr>
        </xsl:if>
        <tr>
          <td nowrap="nowrap"><a class="help" href="directive-dict.html#Status"><xsl:value-of select="$messages/message[@name='status']"/>:</a> </td>
          <td><xsl:value-of select="/modulesynopsis/status"/></td>
        </tr>
        <tr>
          <td nowrap="nowrap"><a class="help" href="directive-dict.html#Module"><xsl:value-of select="$messages/message[@name='module']"/>:</a> </td>
          <td>
            <xsl:if test="modulelist"><xsl:apply-templates select="modulelist"/></xsl:if>
            <xsl:if test="not(modulelist)">
              <xsl:value-of select="/modulesynopsis/name"/>
            </xsl:if>
            </td>
          </tr>
          <xsl:if test="compatibility">
            <tr>
              <td valign="top" align="left" nowrap="nowrap"><a class="help" href="directive-dict.html#Compatibility"><xsl:value-of select="$messages/message[@name='compatibility']"/>:</a> </td>
              <td><xsl:value-of select="compatibility"/></td>
            </tr>
          </xsl:if>
        </table>
      </td></tr></table>

      <xsl:apply-templates select="usage"/>
      <xsl:if test="seealso">
        <p><strong><xsl:value-of select="$messages/message[@name='seealso']"/></strong></p>
        <ul>
          <xsl:for-each select="seealso">
            <li><xsl:apply-templates/></li>
          </xsl:for-each>
        </ul>
      </xsl:if>
      <hr />
    </xsl:if> <!-- not(@location) -->
  </xsl:template> <!-- /directivesynopsis -->

  <!--                                                    -->
  <!-- <contextlist>                                      -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="contextlist">
    <xsl:apply-templates select="context"/>
  </xsl:template> <!-- /contextlist -->

  <!--                                                    -->
  <!-- <context>                                          -->
  <!-- Each entry is separeted with a comma               -->
  <!--                                                    -->
  <xsl:template match="context">
    <xsl:value-of select="." />
    <xsl:if test="not(position()=last())">, </xsl:if>
  </xsl:template> <!-- /context -->

  <!--                                                    -->
  <!-- <modulelist>                                       -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="modulelist">
    <xsl:apply-templates select="module"/>
  </xsl:template> <!-- /modulelist -->

  <!--                                                    -->
  <!-- <example>                                          -->
  <!-- Examples are set in a "colored" table.             -->
  <!--                                                    -->
  <xsl:template match="example">
    <blockquote>
      <table cellpadding="10"><tr><td bgcolor="#eeeeee">
        <xsl:apply-templates select="title" mode="print"/>
        <code><xsl:apply-templates/></code>
      </td></tr></table>
    </blockquote>
  </xsl:template> <!-- /example -->

  <!--                                                    -->
  <!-- <example><title>                                   -->
  <!--                                                    -->
  <xsl:template match="example/title" mode="print">
    <p align="center"><strong><xsl:apply-templates/></strong></p>
  </xsl:template> <!-- /example/title -->

  <!--                                                    -->
  <!-- <example><title>                                   -->
  <!--                                                    -->
  <xsl:template match="example/title"></xsl:template>

  <!--                                                    -->
  <!-- <note>                                             -->
  <!-- Notes are placed in a table. Uses different back-  -->
  <!-- ground colors, depending on type of note.          -->
  <!--                                                    -->
  <xsl:template match="note">
  <blockquote>
  <table><tr><td>
   <xsl:choose>
    <xsl:when test="@type='warning'">
     <xsl:attribute name="bgcolor">#ffe5f5</xsl:attribute>
    </xsl:when>
    <xsl:otherwise>
     <xsl:attribute name="bgcolor">#e0e5f5</xsl:attribute>
    </xsl:otherwise>
   </xsl:choose>
     <xsl:apply-templates/>
  </td></tr></table>
  </blockquote>
  </xsl:template>  <!-- /note -->


  <!--                                                    -->
  <!-- <note><title>                                      -->
  <!--                                                    -->
  <xsl:template match="note/title">
     <p align="center"><strong><xsl:apply-templates/></strong></p>
  </xsl:template> <!-- /note/title -->

  <!--                                                    -->
  <!-- <directive>                                        -->
  <!-- Inserts link to another directive, which might be  -->
  <!-- in another module. References are converted into   --> 
  <!-- lower case.                                        -->
  <!--                                                    -->
  <xsl:template match="directive" name="directive">
    <xsl:if test="@module">
      <xsl:variable name="module">
        <xsl:value-of select="./@module"/>
      </xsl:variable>
      <xsl:variable name="directive">
        <xsl:value-of select="."/>
      </xsl:variable>
      <xsl:variable name="lowerdirective" select="translate($directive, $uppercase, $lowercase)" />
      <xsl:choose>
      <xsl:when test="@module=/modulesynopsis/name">
        <a class="directive" href="#{$lowerdirective}"><code class="directive"><xsl:if test="./@type='section'">&lt;</xsl:if><xsl:value-of select="."/><xsl:if test="./@type='section'">&gt;</xsl:if></code></a>
      </xsl:when>
      <xsl:otherwise>
        <a class="directive" href="{$path}/mod/{$module}.html#{$lowerdirective}"><code class="directive"><xsl:if test="./@type='section'">&lt;</xsl:if><xsl:value-of select="."/><xsl:if test="./@type='section'">&gt;</xsl:if></code></a>
      </xsl:otherwise>
      </xsl:choose>
    </xsl:if>
    <xsl:if test="not(@module)">
       <code class="directive"><xsl:if test="./@type='section'">&lt;</xsl:if><xsl:value-of select="."/><xsl:if test="./@type='section'">&gt;</xsl:if></code>
    </xsl:if>
  </xsl:template> <!-- /directive -->

  <!--                                                    -->
  <!-- <module>                                           -->
  <!-- Inserts a link to refereed module                  -->
  <!--                                                    -->
  <xsl:template match="module" name="module">
    <code><a href="{$path}/mod/{.}.html"><xsl:value-of select="."/></a></code><xsl:if test="parent::modulelist"><xsl:if test="not(position()=last())">, </xsl:if>
    </xsl:if>
  </xsl:template> <!-- /module -->

  <!--                                                    -->
  <!-- <related>                                           -->
  <!--                                                    -->
  <xsl:template match="related">
  <table border="1">
    <tr><td valign="top"><strong><xsl:value-of
    select="$messages/message[@name='relatedmodules']"/></strong><br /><br />
      <xsl:apply-templates select="modulelist"/>
    </td><td valign="top"><strong><xsl:value-of
    select="$messages/message[@name='relateddirectives']"/></strong><br
    /><br />
      <xsl:apply-templates select="directivelist"/>
    </td></tr></table>
  </xsl:template>
     
  <xsl:template match="related/modulelist">
      <xsl:for-each select="module">
        <xsl:call-template name="module"/><br />
      </xsl:for-each>
  </xsl:template>

  <xsl:template match="related/directivelist">
      <xsl:for-each select="directive">
       <xsl:call-template name="directive"/><br />
      </xsl:for-each>
   </xsl:template>


  <!--                                                    -->
  <!-- <summary>                                          -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="summary">
    <xsl:apply-templates/>
  </xsl:template> <!-- /summary -->

  <!--                                                    -->
  <!-- <description>                                      -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="description">
    <xsl:apply-templates/>
  </xsl:template> <!-- /description -->

  <!--                                                    -->
  <!-- <usage>                                            -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="usage">
    <xsl:apply-templates/>
  </xsl:template> <!-- /usage -->

  <!--                                                    -->
  <!-- <syntax>                                           -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="syntax">
    <xsl:apply-templates/>
  </xsl:template> <!-- /syntax -->

  <!--                                                    -->
  <!-- Process everything else by just passing it through -->
  <!--                                                    -->
  <xsl:template match="*|@*">
    <xsl:copy>
      <xsl:apply-templates select="@*|*|text()"/>
    </xsl:copy>
  </xsl:template>

</xsl:stylesheet>
