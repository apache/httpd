<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!--                                                          -->
  <!-- Please, don't hard-code output strings! Use the language -->
  <!-- files and the translation "stuff"...                     -->
  <!--                                                          -->

  <!-- Constants used for case translation -->
  <xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'" />
  <xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

  <!--
    space separated list of blockelements defined in common.dtd
    used for inline content catching in <example>s
  -->
  <xsl:variable name="blockelements">
    p  example  note  table  ul  ol  dl  pre  img  blockquote
  </xsl:variable>

  <!-- relative path to /manual/ -->
  <xsl:variable name="path" select="document(/*/@metafile)/metafile/relpath" />

  <!-- load outsourced page types -->
  <xsl:include href="moduleindex.xsl"/>
  <xsl:include href="directiveindex.xsl"/>
  <xsl:include href="manualpage.xsl"/>
  <xsl:include href="synopsis.xsl"/>
  <xsl:include href="sitemap.xsl"/>
  <xsl:include href="indexpage.xsl"/>
  <xsl:include href="quickreference.xsl"/>

  <!-- make sure, we set relative anchors
       only, if we're actually transforming
       a modulefile (see <directive>) -->
  <xsl:variable name="in-modulesynopsis"><xsl:choose>
    <xsl:when test="/quickreference">0</xsl:when>

    <xsl:otherwise>1</xsl:otherwise></xsl:choose>
  </xsl:variable>

  <!--                                                            -->
  <!--    Utility templates for constructing pages                -->
  <!--                                                            -->


  <!--                                                            -->
  <!-- HTML head                                                  -->
  <!--                                                            -->
  <xsl:template name="head">
    <head>
      <xsl:comment>
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
              This file is generated from xml source: DO NOT EDIT
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      </xsl:comment>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <title>
        <xsl:choose>
          <xsl:when test="name">
            <xsl:value-of select="name"/>
          </xsl:when>

          <xsl:otherwise>
            <xsl:value-of select="title"/>
          </xsl:otherwise>
        </xsl:choose>

        <xsl:text> </xsl:text>
        <xsl:value-of select="$messages/message[@name='apachetitle']"/>
      </title>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <link title="Main stylesheet"  type="text/css" media="all" rel="stylesheet"
             href="{$path}/style/css/manual.css" />

<xsl:text>
</xsl:text> <!-- insert line break -->

      <link title="No Sidebar - Default font size" type="text/css" media="all"
             rel="alternate stylesheet"
             href="{$path}/style/css/manual-loose-100pc.css"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <link type="text/css" media="print"
             rel="stylesheet"
             href="{$path}/style/css/manual-print.css"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <link rel="shortcut icon" href="{$path}/images/favicon.ico" />
    </head>
  </xsl:template>
  <!-- /head -->


  <!--                                                            -->
  <!-- page top                                                   -->
  <!--                                                            -->
  <xsl:template name="top">
    <div id="page-header">

<xsl:text>
</xsl:text> <!-- insert line break -->

      <xsl:call-template name="super-menu" />

<xsl:text>
</xsl:text> <!-- insert line break -->

      <p class="apache">
        <xsl:value-of select="$messages/message[@name='apachehttpserver']"/>
      </p>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <img src="{$path}/images/feather.gif" alt="" />
    </div> <!-- /page-header -->

<xsl:text>
</xsl:text> <!-- insert line break -->

    <div class="up">
      <a href="./">
        <xsl:if test="parentdocument">
          <xsl:attribute name="href"><xsl:value-of select="parentdocument/@href"/></xsl:attribute>
        </xsl:if>
        <img src="{$path}/images/left.gif" alt="&lt;-" title="&lt;-" />
      </a>
    </div>

<xsl:text>
</xsl:text> <!-- insert line break -->

    <div id="path">

<xsl:text>
</xsl:text> <!-- insert line break -->

      <a href="http://www.apache.org/">
        <xsl:value-of select="$messages/message[@name='apache']"/>
      </a>
      <xsl:text> &gt; </xsl:text>
      <a href="http://httpd.apache.org/">
        <xsl:value-of select="$messages/message[@name='http-server']"/>
      </a>
      <xsl:text> &gt; </xsl:text>
      <a href="http://httpd.apache.org/docs-project/">
        <xsl:value-of select="$messages/message[@name='documentation']"/>
      </a>
      <xsl:if test="not(../indexpage)">
        <xsl:text> &gt; </xsl:text>
        <a href="{$path}/">
          <xsl:value-of select="$messages/message[@name='version']"/>
        </a>
      </xsl:if>
      <xsl:if test="../modulesynopsis or ../directiveindex or ../quickreference">
        <xsl:text> &gt; </xsl:text>
        <a href="./">
          <xsl:value-of select="$messages/message[@name='modules']"/>
        </a>
      </xsl:if>
      <xsl:if test="parentdocument/text()">
        <xsl:text> &gt; </xsl:text>
        <a href="{parentdocument/@href}">
          <xsl:value-of select="parentdocument"/>
        </a>
      </xsl:if>
    </div> <!-- /path -->
  </xsl:template>
  <!-- /top -->


  <!--                                                            -->
  <!-- page bottom                                                -->
  <!--                                                            -->
  <xsl:template name="bottom">
    <div id="footer">

<xsl:text>
</xsl:text> <!-- insert line break -->

      <p class="apache">
        <xsl:value-of select="$messages/message[@name='maintainedby']"/>
        <xsl:text> </xsl:text>
        <a href="http://httpd.apache.org/docs-project/"
          >Apache HTTP Server Documentation Project</a>
      </p>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <xsl:call-template name="super-menu"/>

    </div> <!-- /footer -->
  </xsl:template>
  <!-- /bottom -->


  <!--                                                            -->
  <!-- Process a documentation section                            -->
  <!--                                                            -->
  <xsl:template match="section">

    <xsl:call-template name="toplink"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

    <div class="section">

<xsl:text>
</xsl:text> <!-- insert line break -->

      <!-- Section heading -->
      <h2>
        <xsl:if test="@id">
          <a id="{@id}" name="{@id}">
            <xsl:apply-templates select="title" mode="print"/>
          </a>
        </xsl:if>

        <xsl:if test="not(@id)">
          <xsl:apply-templates select="title" mode="print"/>
        </xsl:if>
      </h2>

      <!-- Section body -->
      <xsl:apply-templates/>

    </div> <!-- /.section -->
  </xsl:template>
  <!-- /section -->


  <!--                                                            -->
  <!-- handle subsections (lower level headings)                  -->
  <!--                                                            -->
  <xsl:template match="section/section">

    <!-- Section heading -->
    <h3>
      <xsl:if test="@id">
        <a id="{@id}" name="{@id}">
          <xsl:apply-templates select="title" mode="print"/>
        </a>
      </xsl:if>

      <xsl:if test="not(@id)">
        <xsl:apply-templates select="title" mode="print"/>
      </xsl:if>
    </h3>

    <!-- Section body -->
    <xsl:apply-templates/>

  </xsl:template>
  <!-- /section/section -->


  <!--                                                            -->
  <!-- handle subsubsections (h4)                                 -->
  <!--                                                            -->
  <xsl:template match="section/section/section">

    <!-- Section heading -->
    <h4>
      <xsl:if test="@id">
        <a id="{@id}" name="{@id}">
          <xsl:apply-templates select="title" mode="print"/>
        </a>
      </xsl:if>

      <xsl:if test="not(@id)">
        <xsl:apply-templates select="title" mode="print"/>
      </xsl:if>
    </h4>

    <!-- Section body -->
    <xsl:apply-templates/>

  </xsl:template>
  <!-- /section/section/section -->


  <!--                                                            -->
  <!-- section nesting > h4 is not supported for now              -->
  <!--                                                            -->
  <xsl:template match="section/section/section/section">
    <xsl:message terminate="yes">
      <xsl:text>FATAL: exceeding maximum section nesting level.

      Perhaps you should consider to split your document into
      several ones...
      </xsl:text>
    </xsl:message>
  </xsl:template>
  <!-- /section/section/section/section -->


  <!--                                                            -->
  <!-- (sub)section titles                                        -->
  <!--                                                            -->
  <xsl:template match="section/title" mode="print">
    <xsl:apply-templates/>
  </xsl:template>

  <xsl:template match="section/title">
    <!-- Don't print the title twice -->
  </xsl:template>
  <!-- /section/title -->


  <!--                                                            -->
  <!-- generate section index                                     -->
  <!--                                                            -->
  <xsl:template match="section" mode="index">

    <xsl:if test="@id">
      <li>
        <img src="{$path}/images/down.gif" alt="" />
        <xsl:text> </xsl:text>
        <a href="#{@id}">
          <xsl:apply-templates select="title" mode="print"/>
        </a>
      </li>

<xsl:text>
</xsl:text> <!-- insert line break -->

    </xsl:if>

    <xsl:if test="not(@id)">
      <li>
        <img src="{$path}/images/down.gif" alt="" />
        <xsl:text> </xsl:text>
        <xsl:apply-templates select="title" mode="print"/>

        <!-- nested sections -->
        <!-- NOT FOR NOW     -->
        <!--
        <xsl:if test="section">
          <ul>
            <xsl:apply-templates select="section" mode="index"/>
          </ul>
        </xsl:if>
        -->
      </li>

<xsl:text>
</xsl:text> <!-- insert line break -->

    </xsl:if>

  </xsl:template>
  <!-- /section index -->


  <!--                                                            -->
  <!-- docs super menu                                            -->
  <!--                                                            -->
  <xsl:template name="super-menu">
    <p class="menu">
      <a href="{$path}/mod/">
        <xsl:value-of select="$messages/message[@name='modules']"/>
      </a>
      <xsl:text> | </xsl:text>
      <a href="{$path}/mod/directives.html">
        <xsl:value-of select="$messages/message[@name='directives']"/>
      </a>
      <xsl:text> | </xsl:text>
      <a href="{$path}/faq/">
        <xsl:value-of select="$messages/message[@name='faq']"/>
      </a>
      <xsl:text> | </xsl:text>
      <a href="{$path}/glossary.html">
        <xsl:value-of select="$messages/message[@name='glossary']"/>
      </a>
      <xsl:text> | </xsl:text>
      <a href="{$path}/sitemap.html">
        <xsl:value-of select="$messages/message[@name='sitemap']"/>
      </a>
    </p>
  </xsl:template>
  <!-- /super-menu -->


  <!--                                                    -->
  <!-- <example>                                          -->
  <!-- iterate over *all* nodes; bare text and other      -->
  <!-- inline stuff is wrapped into <p><code>, block      -->
  <!-- level elements (defined in $blockelements) are     -->
  <!-- applied "as is"                                    -->
  <!--                                                    -->
  <xsl:variable name="blocks"
              select="concat(' ', normalize-space($blockelements), ' ')"/>

  <xsl:template match="example">
    <div class="example">
       <xsl:apply-templates select="title" mode="print"/>

       <xsl:for-each select="./node()">
         <xsl:variable name="is-block-node" select="boolean(contains($blocks, concat(' ',local-name(),' ')))"/>
         <xsl:variable name="bb" select="count(preceding-sibling::*[contains($blocks,concat(' ',local-name(),' '))])"/>

         <xsl:if test="$is-block-node or position()=last()">
           <xsl:variable name="content">
             <xsl:apply-templates select="preceding-sibling::node()[count(preceding-sibling::*[contains($blocks,concat(' ',local-name(),' '))]) &gt;= $bb]"/>
             <xsl:apply-templates select="self::node()[not($is-block-node)]"/>
           </xsl:variable>

           <!-- apply bare text only, if it's not only \s or empty -->
           <xsl:if test="normalize-space($content) != ''">
             <p><code>
               <xsl:copy-of select="$content"/>
             </code></p>
           </xsl:if>

           <xsl:apply-templates select="self::node()[$is-block-node]"/>
         </xsl:if>

       </xsl:for-each>
       <!-- /node() -->

     </div> <!-- /.example -->
  </xsl:template>
  <!-- /example -->


  <!--                                                    -->
  <!-- example/title                                      -->
  <!--                                                    -->
  <xsl:template match="example/title" mode="print">
    <h3>
        <xsl:apply-templates/>
    </h3>
  </xsl:template>

  <xsl:template match="example/title">
    <!-- don't print twice -->
  </xsl:template>
  <!-- /example/title -->


  <!--                                                    -->
  <!-- indent                                             -->
  <!--                                                    -->
  <xsl:template match="indent">
    <span class="indent">
      <xsl:apply-templates/>
    </span>
  </xsl:template>
  <!-- /indent -->


  <!--                                                    -->
  <!-- <note>                                             -->
  <!-- Notes are placed in a table. Uses different back-  -->
  <!-- ground colors, depending on type of note.          -->
  <!--                                                    -->
  <xsl:template match="note">
    <div class="note">
      <xsl:if test="@type='warning'">
        <xsl:attribute name="class">warning</xsl:attribute>
      </xsl:if>

      <xsl:apply-templates/>
    </div>
  </xsl:template>
  <!-- /note -->


  <!--                                                    -->
  <!-- <note><title>                                      -->
  <!--                                                    -->
  <xsl:template match="note/title">
    <h3>
      <xsl:apply-templates/>
    </h3>
  </xsl:template>
  <!-- /note/title -->


  <!--                                                    -->
  <!-- <directive>                                        -->
  <!-- Inserts link to another directive, which might be  -->
  <!-- in another module. References are converted into   -->
  <!-- lower case.                                        -->
  <!--                                                    -->
  <xsl:template match="directive" name="directive">
    <code class="directive">

      <xsl:if test="@module">
        <xsl:variable name="lowerdirective" select="translate(., $uppercase, $lowercase)"/>

        <xsl:choose>
          <xsl:when test="$in-modulesynopsis = '1' and @module = /modulesynopsis/name">
            <a href="#{$lowerdirective}">
              <xsl:if test="@type='section'">&lt;</xsl:if>
              <xsl:value-of select="."/>
              <xsl:if test="@type='section'">&gt;</xsl:if>
            </a>
          </xsl:when>

          <xsl:otherwise>
            <xsl:variable name="obs_">
              <xsl:if test="@status = 'obsolete'">obs_</xsl:if>
            </xsl:variable>

            <a href="{$path}/mod/{$obs_}{@module}.html#{$lowerdirective}">
              <xsl:if test="@type='section'">&lt;</xsl:if>
              <xsl:value-of select="."/>
              <xsl:if test="@type='section'">&gt;</xsl:if>
            </a>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:if>

      <xsl:if test="not(@module)">
        <xsl:if test="@type='section'">&lt;</xsl:if>
        <xsl:value-of select="."/>
        <xsl:if test="@type='section'">&gt;</xsl:if>
      </xsl:if>

    </code>
  </xsl:template>
  <!-- /directive -->


  <!--                                                    -->
  <!-- <module>                                           -->
  <!-- Inserts a link to refereed module                  -->
  <!--                                                    -->
  <xsl:template match="module" name="module">
    <xsl:variable name="obs_">
      <xsl:if test="@status = 'obsolete'">obs_</xsl:if>
    </xsl:variable>

    <code class="module">
      <a href="{$path}/mod/{$obs_}{.}.html">
        <xsl:value-of select="."/>
      </a>
    </code>
  </xsl:template>
  <!-- /module -->


  <!--                                                    -->
  <!-- <related>                                          -->
  <!--                                                    -->
  <xsl:template match="related">
    <table class="related">
      <tr>
        <th>
          <xsl:value-of select="$messages/message[@name='relatedmodules']"/>
        </th>
        <th>
          <xsl:value-of select="$messages/message[@name='relateddirectives']"/>
        </th>
      </tr>

      <tr>
        <td>
          <xsl:if test="count(modulelist/*) &gt; 0">
	    <ul>
	      <xsl:apply-templates select="modulelist"/>
	    </ul>
	  </xsl:if>
        </td>

        <td>
          <xsl:if test="count(directivelist/*) &gt; 0">
            <ul>
	      <xsl:apply-templates select="directivelist"/>
            </ul>
          </xsl:if>
        </td>
      </tr>
    </table>
  </xsl:template>
  <!-- /related -->


  <xsl:template match="related/modulelist">
    <xsl:for-each select="module">
      <li>
        <xsl:call-template name="module"/>
      </li>
    </xsl:for-each>
  </xsl:template>



  <xsl:template match="related/directivelist">
    <xsl:for-each select="directive">
      <li>
        <xsl:call-template name="directive"/>
      </li>
    </xsl:for-each>
  </xsl:template>


  <!--                                                    -->
  <!-- <table>                                            -->
  <!--                                                    -->
  <xsl:template match="table">
    <table>
      <xsl:if test="@border">
        <xsl:attribute name="class">bordered</xsl:attribute>
      </xsl:if>

      <xsl:choose>
        <xsl:when test="@style = 'zebra'">
          <xsl:for-each select="tr">

            <tr><xsl:choose>
              <xsl:when test="count(td) = 0">
                <xsl:attribute name="class">header</xsl:attribute>
              </xsl:when>

              <xsl:when test="position() mod 2 = (count(preceding-sibling::*[count(td) = 0]) mod 2)">
                <xsl:attribute name="class">odd</xsl:attribute>
              </xsl:when></xsl:choose>

              <xsl:apply-templates />
            </tr>

<xsl:text>
</xsl:text> <!-- insert line break -->

          </xsl:for-each>
        </xsl:when>

        <xsl:otherwise>
          <xsl:apply-templates />
        </xsl:otherwise>
      </xsl:choose>
    </table>

  </xsl:template>
  <!-- /table -->


  <!--                                                    -->
  <!-- <ol type                                           -->
  <!--                                                    -->
  <xsl:template match="ol">
    <ol>
      <xsl:if test="@type = 'A'">
        <xsl:attribute name="class">up-A</xsl:attribute>
      </xsl:if>

      <xsl:apply-templates/>
    </ol>
  </xsl:template>
  <!-- /ol type -->


  <!--                                                    -->
  <!-- <summary>                                          -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="summary">
    <xsl:apply-templates/>
  </xsl:template>
  <!-- /summary -->


  <!--                                                    -->
  <!-- <description>                                      -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="description">
    <xsl:apply-templates/>
  </xsl:template>
  <!-- /description -->


  <!--                                                    -->
  <!-- <hint>                                             -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="hint">
    <xsl:apply-templates/>
  </xsl:template>
  <!-- /description -->


  <!--                                                    -->
  <!-- <usage>                                            -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="usage">
    <xsl:apply-templates/>
  </xsl:template>
  <!-- /usage -->


  <!--                                                    -->
  <!-- <syntax>                                           -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="syntax">
    <xsl:apply-templates/>
  </xsl:template>
  <!-- /syntax -->

  <!--                                                    -->
  <!-- <default>                                          -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="default">
    <xsl:apply-templates/>
  </xsl:template>
  <!-- /default -->


  <!--                                                    -->
  <!-- toplink                                            -->
  <!--                                                    -->
  <xsl:template name="toplink">
    <div class="top">
      <a href="#page-header"><img src="{$path}/images/up.gif" alt="top" /></a>
    </div>
  </xsl:template>
  <!-- /toplink -->


  <!--                                                    -->
  <!-- <transnote>                                        -->
  <!--                                                    -->
  <xsl:template match="transnote">
    <span class="transnote">
      <xsl:text>(</xsl:text><em>
      <xsl:value-of select="$messages/message[@name='transnote']"/>
      </em><xsl:text> </xsl:text>
      <xsl:apply-templates/>
      <xsl:text>)</xsl:text>
    </span>
  </xsl:template>
  <!-- /note/title -->


  <!--                                                    -->
  <!-- Process everything else by just passing it through -->
  <!--                                                    -->
  <xsl:template match="*|@*">
    <xsl:copy>
      <xsl:apply-templates select="@*|*|text()"/>
    </xsl:copy>
  </xsl:template>


  <!--                                                    -->
  <!-- create a letter bar                                -->
  <!-- used in several documents                          -->
  <!--                                                    -->
  <xsl:template name="letter-bar">
  <xsl:param name="letters"/>
  <xsl:param name="first"/>

    <xsl:if test="not($first)">
      <xsl:text> | </xsl:text>
    </xsl:if>

    <a href="#{substring($letters,1,1)}">
      <xsl:text>&nbsp;</xsl:text>
      <xsl:value-of select="substring($letters,1,1)"/>
      <xsl:text>&nbsp;</xsl:text>
    </a>

    <xsl:if test="string-length($letters) &gt; 1">
      <xsl:call-template name="letter-bar">
        <xsl:with-param name="letters" select="substring($letters,2)"/>
        <xsl:with-param name="first" select="false()"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>


  <!--                                                    -->
  <!-- template(s) for collecting all start letters       -->
  <!-- of directives                                      -->
  <!-- used in several documents                          -->
  <!--                                                    -->
  <xsl:template name="directive-startletters">
  <xsl:param name="directives"/>

    <xsl:call-template name="_squeeze-letters">
      <xsl:with-param name="lastletter" select="''"/>

      <xsl:with-param name="letters">
        <xsl:for-each select="$directives">
        <xsl:sort select="name"/>
          <xsl:value-of select="translate(substring(normalize-space(name),1,1),$lowercase,$uppercase)"/>
        </xsl:for-each>
      </xsl:with-param>
    </xsl:call-template>

  </xsl:template>

  <xsl:template name="_squeeze-letters">
  <xsl:param name="letters"/>
  <xsl:param name="lastletter"/>

    <xsl:variable name="current" select="substring($letters,1,1)"/>

    <xsl:if test="$lastletter != $current">
      <xsl:value-of select="$current"/>
    </xsl:if>

    <xsl:if test="string-length($letters) &gt; 1">
      <xsl:call-template name="_squeeze-letters">
        <xsl:with-param name="letters" select="substring($letters,2)"/>
        <xsl:with-param name="lastletter" select="$current"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>


  <xsl:template name="module-translatename">
  <xsl:param name="name"/>

    <xsl:variable name="sname" select="translate($name,$lowercase,$uppercase)"/>

    <xsl:choose>
      <xsl:when test="starts-with($sname,'MOD_') or starts-with($sname,'MPM_')">
        <xsl:value-of select="substring($name, 5)"/>
      </xsl:when>
      <xsl:when test="starts-with($sname,'MPMT_')">
        <xsl:value-of select="substring($name, 6)"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$name"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>
  <!-- /module-translatename -->

</xsl:stylesheet>