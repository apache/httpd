<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE xsl:stylesheet
 [ <!ENTITY lf SYSTEM "../xsl/util/lf.xml"> ]
>

<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<!--                                                    -->
<!-- <sitemap>                                          -->
<!-- Process an entire document into an HTML page       -->
<!--                                                    -->
<xsl:template match="/sitemap">

<!-- static information -->
<!-- ================== -->

  <xsl:text>[OPTIONS]</xsl:text>&lf;
  <xsl:text>Binary TOC=No</xsl:text>&lf;
  <xsl:text>Compatibility=1.0</xsl:text>&lf;

  <!-- e.g. manual.en.chm -->
  <xsl:text>Compiled file=..\manual.</xsl:text>
  <xsl:value-of select="$messages/@lang" />
  <xsl:text>.chm</xsl:text>&lf;

  <xsl:text>Contents file=toc.hhc</xsl:text>&lf;
  <xsl:text>Default Window=Main</xsl:text>&lf;
  <xsl:text>Default topic=index.html</xsl:text>&lf;

  <!-- compiler related -->
  <xsl:text>Display compile progress=Yes</xsl:text>&lf;
  <xsl:text>Enhanced decompilation=Yes</xsl:text>&lf;

  <!-- search related -->
  <xsl:text>Full-text search=Yes</xsl:text>&lf;
  <xsl:text>Language=</xsl:text>
  <xsl:value-of select="$hhp-lang" />&lf;

  <!-- title of the help file -->
  <xsl:text>Title=</xsl:text>
  <xsl:value-of select="$messages/message[@name='apachehttpserver']"/>&lf;

  &lf;

  <!-- window definition                                             -->
  <!-- (don't care about the magic values, they are mostly generated -->
  <!--  from the HTML Help workshop)                                 -->
  <xsl:text>[WINDOWS]</xsl:text>&lf;
  <xsl:text>Main=</xsl:text>

  <!-- title -->
  <xsl:text>"</xsl:text>
  <xsl:value-of select="$messages/message[@name='apachehttpserver']"/>
  <xsl:text>",</xsl:text>

  <!-- toc file -->
  <xsl:text>"toc.hhc",</xsl:text>

  <!-- index file (currently none) -->
  <xsl:text>,</xsl:text>

  <!-- default file (startup) -->
  <xsl:text>"index.html",</xsl:text>

  <!-- Home button file -->
  <xsl:text>"index.html",</xsl:text>

  <!-- Jump 1 url, text -->
  <xsl:text>,,</xsl:text>

  <!-- Jump 2 url, text -->
  <xsl:text>,,</xsl:text>

  <!-- navigation pane style, initial width (px) -->
  <xsl:text>0x1e357e,180,</xsl:text>
  
  <!-- button mask -->
  <xsl:text>0x10305e,</xsl:text>
  
  <!-- Initial Position [Left, Top, Right, Bottom] -->
  <xsl:text>[0,0,600,380],</xsl:text>
  
  <!-- style, extended style -->
  <xsl:text>0xb7cf0000,,</xsl:text>
  
  <!-- flag: navigation initial closed (=1) -->
  <xsl:text>,</xsl:text>
  
  <!-- unknown -->
  <xsl:text>,</xsl:text>
  
  <!-- default pane -->
  <xsl:text>,</xsl:text>
  
  <!-- unknown, unknown -->
  <xsl:text>,0</xsl:text>&lf;

  &lf;
  
<!-- file list -->
<!-- ========= -->
  <xsl:text>[FILES]</xsl:text>&lf;

  <!-- not automatically sucked in. (because only @import()ed) -->
  <xsl:text>style\css\manual.css</xsl:text>&lf;
  <xsl:text>style\css\manual-loose-100pc.css</xsl:text>&lf;

  <!-- include project file itself for easier recompiling -->
  <xsl:text>manual.hhp</xsl:text>&lf;

  <xsl:for-each select="category">
    <xsl:for-each select="page[@href]">
      <xsl:variable name="local"><xsl:choose>
        <xsl:when test="contains(@href, '#') and substring(@href, string-length(substring-before(@href, '#')), 1) = '/'">
          <xsl:value-of select="substring-before(@href, '#')" />
          <xsl:text>index.html</xsl:text>
        </xsl:when>

        <xsl:when test="substring(@href,string-length(@href),1) = '/'">
          <xsl:value-of select="@href"/>
          <xsl:text>index.html</xsl:text>
        </xsl:when>

        <xsl:otherwise><xsl:value-of select="@href"/></xsl:otherwise></xsl:choose>
      </xsl:variable>
        
      <xsl:call-template name="back-slash">
        <xsl:with-param name="file" select="$local"/>
      </xsl:call-template>&lf;
    </xsl:for-each> <!-- / page -->

    <xsl:apply-templates select="modulefilelist"/>
  </xsl:for-each>&lf;

</xsl:template>

<!-- module files -->
<xsl:template match="category/modulefilelist">
  <xsl:for-each select="modulefile">
    <xsl:text>mod\</xsl:text>
    <xsl:value-of select="substring-before(normalize-space(.), '.xml')"/>
    <xsl:text>.html</xsl:text>&lf;
  </xsl:for-each>
</xsl:template>

<!-- turn slashes to backslashes -->
<xsl:template name="back-slash">
<xsl:param name="file"/>

  <xsl:choose>
    <xsl:when test="contains($file, '/')">
      <xsl:value-of select="substring-before($file, '/')"/>
      <xsl:text>\</xsl:text>

      <xsl:call-template name="back-slash">
        <xsl:with-param name="file" select="substring-after($file, '/')"/>
      </xsl:call-template>
    </xsl:when>

    <xsl:otherwise>
      <xsl:value-of select="$file"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

</xsl:stylesheet>
