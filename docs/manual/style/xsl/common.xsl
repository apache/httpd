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
  <xsl:variable name="path">
    <xsl:choose>
      <xsl:when test="*/relativepath/@href">
        <xsl:value-of select="*/relativepath/@href"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="'..'"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>

  <!-- load outsourced page types -->
  <xsl:include href="moduleindex.xsl"/>
  <xsl:include href="directiveindex.xsl"/>
  <xsl:include href="manualpage.xsl"/>
  <xsl:include href="synopsis.xsl"/>

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
      
      <link title="right sidebar - blue (font 100%)"    type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-right-100pc.css" />
      <link title="right sidebar - blue (font 90%)"     type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-right-90pc.css" />
      <link title="right sidebar - blue (font fix 15)"  type="text/css" media="all" rel="stylesheet"
             href="{$path}/style/css/manual-sbar-right-fix15.css" />
      <link title="right sidebar - blue (font fix 13)"  type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-right-fix13.css" />
      <link title="right sidebar - black (font 100%)"   type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-right-100pc-b.css" />
      <link title="right sidebar - black (font 90%)"    type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-right-90pc-b.css" />
      <link title="right sidebar - black (font fix 15)" type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-right-fix15-b.css" />
      <link title="right sidebar - black (font fix 13)" type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-right-fix13-b.css" />

      <link title="left sidebar - blue (font 100%)"     type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-left-100pc.css" />
      <link title="left sidebar - blue (font 90%)"      type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-left-90pc.css" />
      <link title="left sidebar - blue (font fix 15)"   type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-left-fix15.css" />
      <link title="left sidebar - blue (font fix 13)"   type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-left-fix13.css" />
      <link title="left sidebar - black (font 100%)"    type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-left-100pc-b.css" />
      <link title="left sidebar - black (font 90%)"     type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-left-90pc-b.css" />
      <link title="left sidebar - black (font fix 15)"  type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-left-fix15-b.css" />
      <link title="left sidebar - black (font fix 13)"  type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-sbar-left-fix13-b.css" />

      <link title="loose style - blue (font 100%)"      type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-loose-100pc.css" />
      <link title="loose style - blue (font 90%)"       type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-loose-90pc.css" />
      <link title="loose style - blue (font fix 15)"    type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-loose-fix15.css" />
      <link title="loose style - blue (font fix 13)"    type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-loose-fix13.css" />
      <link title="loose style - black (font 100%)"     type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-loose-100pc-b.css" />
      <link title="loose style - black (font 90%)"      type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-loose-90pc-b.css" />
      <link title="loose style - black (font fix 15)"   type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-loose-fix15-b.css" />
      <link title="loose style - black (font fix 13)"   type="text/css" media="all" rel="alternate stylesheet"
             href="{$path}/style/css/manual-loose-fix13-b.css" />

      <link rel="shortcut icon" href="{$path}/images/favicon.ico" />
    </head>
  </xsl:template>
  <!-- /head -->


  <!--                                                            -->
  <!-- page top                                                   -->
  <!--                                                            -->
  <xsl:template name="top">
    <div id="page-header">
      <xsl:call-template name="super-menu" />

      <p class="apache">
        <xsl:value-of select="$messages/message[@name='apachehttpserver']"/>
      </p>

      <img src="{$path}/images/feather.gif" alt="" />
    </div> <!-- /page-header -->

    <div class="up">
      <a href="./"><img src="{$path}/images/left.gif" alt="&lt;-" title="&lt;-" /></a>
    </div>

    <div id="path">

      <!-- XXX: choose just for now, so it works until the
           translations are done! -->
      <xsl:choose>
        <xsl:when test="$messages/message[@name='maintainedby']">
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
          <xsl:text> &gt; </xsl:text>
          <a href="{$path}/">
            <xsl:value-of select="$messages/message[@name='version']"/>
          </a>
          <xsl:if test="../modulesynopsis or ../directiveindex">
            <xsl:text> &gt; </xsl:text>
            <a href="./">
              <xsl:value-of select="$messages/message[@name='modules']"/>
            </a>
          </xsl:if>
        </xsl:when>

        <xsl:otherwise>
          <a href="http://www.apache.org/">Apache</a>
          <xsl:text> &gt; </xsl:text>
          <a href="http://httpd.apache.org/">HTTP Server</a>
          <xsl:text> &gt; </xsl:text>
          <a href="http://httpd.apache.org/docs-project/">Documentation</a>
          <xsl:text> &gt; </xsl:text>
          <a href="{$path}/">Version 2.0</a>
          <xsl:if test="../modulesynopsis or ../directiveindex">
            <xsl:text> &gt; </xsl:text>
            <a href="./">Modules</a>
          </xsl:if>
        </xsl:otherwise>
      </xsl:choose>

    </div> <!-- /path -->
  </xsl:template>
  <!-- /top -->


  <!--                                                            -->
  <!-- page bottom                                                -->
  <!--                                                            -->
  <xsl:template name="bottom">
    <div id="footer">
      <p class="apache">

        <!-- XXX: choose just for now, so it works until the
             translations are done! -->
        <xsl:choose>
          <xsl:when test="$messages/message[@name='maintainedby']">
            <xsl:value-of select="$messages/message[@name='maintainedby']"/>
          </xsl:when>

          <xsl:otherwise>
            <xsl:text>Maintained by the</xsl:text>
          </xsl:otherwise>
        </xsl:choose>

        <xsl:text> </xsl:text>
        <a href="http://httpd.apache.org/docs-project/">Apache HTTP Server Documentation Project</a>
      </p>

      <xsl:call-template name="super-menu"/>

    </div> <!-- /footer -->
  </xsl:template>
  <!-- /bottom -->


  <!--                                                            -->
  <!-- Process a documentation section                            -->
  <!--                                                            -->
  <xsl:template match="section">

    <xsl:call-template name="toplink"/>

    <div class="section">

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
    </xsl:if>

  </xsl:template>
  <!-- /section index -->


  <!--                                                            -->
  <!-- docs super menu                                            -->
  <!--                                                            -->
  <xsl:template name="super-menu">
    <p class="menu">

      <!-- XXX: choose just for now, so it works until the
           translations are done! -->
      <xsl:choose>
        <xsl:when test="$messages/message[@name='maintainedby']">
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
        </xsl:when>

        <xsl:otherwise>
          <a href="{$path}/mod/">Modules</a>
          <xsl:text> | </xsl:text>
          <a href="{$path}/mod/directives.html">Directives</a>
          <xsl:text> | </xsl:text>
          <a href="{$path}/faq/">FAQ</a>
          <xsl:text> | </xsl:text>
          <a href="{$path}/glossary.html">Glossary</a>
          <xsl:text> | </xsl:text>
          <a href="{$path}/sitemap.html">Sitemap</a>
        </xsl:otherwise>
      </xsl:choose>

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
  <!-- <note>                                             -->
  <!-- Notes are placed in a table. Uses different back-  -->
  <!-- ground colors, depending on type of note.          -->
  <!--                                                    -->
  <xsl:template match="note">
    <xsl:choose>
       <xsl:when test="@type='warning'">
         <div class="warning">
           <xsl:apply-templates/>
         </div>
       </xsl:when>

       <xsl:otherwise>
         <div class="note">
           <xsl:apply-templates/>
         </div>
       </xsl:otherwise>
     </xsl:choose>
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
          <xsl:when test="@module = /modulesynopsis/name">
            <a href="#{$lowerdirective}">
              <xsl:if test="@type='section'">&lt;</xsl:if>
              <xsl:value-of select="."/>
              <xsl:if test="@type='section'">&gt;</xsl:if>
            </a>
          </xsl:when>

          <xsl:otherwise>
            <a href="{$path}/mod/{@module}.html#{$lowerdirective}">
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
    <code class="module">
      <a href="{$path}/mod/{.}.html">
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
  <!-- <table border>                                     -->
  <!--                                                    -->
  <xsl:template match="table">
    <xsl:if test="@border">
      <table class="bordered">
        <xsl:apply-templates/>
      </table>
    </xsl:if>

    <xsl:if test="not(@border)">
      <table>
        <xsl:apply-templates/>
      </table>
    </xsl:if>
  </xsl:template>
  <!-- /table border -->


  <!--                                                    -->
  <!-- <ol type                                           -->
  <!--                                                    -->
  <xsl:template match="ol">
    <xsl:if test="@type = 'A'">
      <ol class="up-A">
        <xsl:apply-templates/>
      </ol>
    </xsl:if>

    <xsl:if test="not(@type)">
      <ol>
        <xsl:apply-templates/>
      </ol>
    </xsl:if>
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
  <!-- toplink                                            -->
  <!--                                                    -->
  <xsl:template name="toplink">
    <div class="top">
      <a href="#page-header"><img src="{$path}/images/up.gif" alt="top" /></a>
    </div>
  </xsl:template> 
  <!-- /toplink -->


  <!--                                                    -->
  <!-- Process everything else by just passing it through -->
  <!--                                                    -->
  <xsl:template match="*|@*">
    <xsl:copy>
      <xsl:apply-templates select="@*|*|text()"/>
    </xsl:copy>
  </xsl:template>

</xsl:stylesheet>
