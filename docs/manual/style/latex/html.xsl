<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">


<!-- ==================================================================== -->
<!-- Ordinary HTML that must be converted to latex                        -->
<!-- ==================================================================== -->

<xsl:template match="ul">
<xsl:text>\begin{itemize}
</xsl:text>
<xsl:apply-templates/>
<xsl:text>\end{itemize}
</xsl:text>
</xsl:template>

<xsl:template match="ol">
<xsl:text>\begin{enumerate}
</xsl:text>
<xsl:apply-templates/>
<xsl:text>\end{enumerate}
</xsl:text>
</xsl:template>

<xsl:template match="li">
<xsl:text>\item </xsl:text>
<xsl:apply-templates/>
<xsl:text>
</xsl:text>
</xsl:template>

<xsl:template match="dl">
<xsl:text>\begin{description}
</xsl:text>
<xsl:apply-templates/>
<xsl:text>\end{description}
</xsl:text>
</xsl:template>

<xsl:template match="dt">
<xsl:text>\item[</xsl:text><xsl:apply-templates/>
<xsl:text>] </xsl:text>
</xsl:template>

<xsl:template match="dd">
<xsl:apply-templates/>
</xsl:template>

<!-- Latex doesn't like successive line breaks, so replace any
     sequence of two or more br separated only by white-space with
     one line break followed by smallskips. -->
<xsl:template match="br">
<xsl:choose>
<xsl:when test="name(preceding-sibling::node()[1])='br'">
<xsl:text>\smallskip </xsl:text>
</xsl:when>
<xsl:when test="name(preceding-sibling::node()[2])='br'">
  <xsl:choose>
  <xsl:when test="normalize-space(preceding-sibling::node()[1])=''">
    <xsl:text>\smallskip </xsl:text>
  </xsl:when>
  <xsl:otherwise>
    <!-- Don't put a line break if we are the last thing -->
    <xsl:if test="not(position()=last()) and not(position()=last()-1 and normalize-space(following-sibling::node()[1])='')">
      <xsl:text>\\ </xsl:text>
    </xsl:if>
  </xsl:otherwise>
  </xsl:choose>
</xsl:when>
<xsl:otherwise>
    <!-- Don't put a line break if we are the last thing -->
    <xsl:if test="not(position()=last()) and not(position()=last()-1 and normalize-space(following-sibling::node()[1])='')">
      <xsl:text>\\ </xsl:text>
    </xsl:if>
</xsl:otherwise>
</xsl:choose>
</xsl:template>

<xsl:template match="p">
<xsl:apply-templates/>
<xsl:text>\par
</xsl:text>
</xsl:template>

<xsl:template match="code">
<xsl:text>\texttt{</xsl:text>
<xsl:apply-templates/>
<xsl:text>}</xsl:text>
</xsl:template>

<xsl:template match="strong">
<xsl:text>\textbf{</xsl:text>
<xsl:apply-templates/>
<xsl:text>}</xsl:text>
</xsl:template>

<xsl:template match="em">
<xsl:text>\textit{</xsl:text>
<xsl:apply-templates/>
<xsl:text>}</xsl:text>
</xsl:template>

<!-- Value-of used here explicitly because we don't wan't latex-escaping
performed.  Of course, this will conflict with html where some tags are
interpreted in pre -->
<xsl:template match="pre">
<xsl:text>\begin{verbatim}
</xsl:text>
<xsl:value-of select="."/>
<xsl:text>\end{verbatim}
</xsl:text>
</xsl:template>

<xsl:template match="blockquote">
<xsl:text>\begin{quotation}
</xsl:text>
<xsl:apply-templates/>
<xsl:text>\end{quotation}
</xsl:text>
</xsl:template>

<!-- XXX: We need to deal with table headers -->

<xsl:template match="table">
<xsl:text>\fbox{\begin{tabular}{</xsl:text>
<xsl:choose>
<xsl:when test="columnspec">
  <xsl:for-each select="columnspec/column">
    <xsl:text>l</xsl:text>
    <xsl:if test="../../@border and not(position()=last())">
      <xsl:text>|</xsl:text>
    </xsl:if>
  </xsl:for-each>
</xsl:when>
<xsl:otherwise>
  <xsl:for-each select="tr[1]/*">
    <xsl:text>l</xsl:text>
    <xsl:if test="../../@border and not(position()=last())">
      <xsl:text>|</xsl:text>
    </xsl:if>
  </xsl:for-each>
</xsl:otherwise>
</xsl:choose>
<xsl:text>}</xsl:text>
<xsl:apply-templates select="tr"/>
<xsl:text>\end{tabular}}
</xsl:text>
</xsl:template>

<xsl:template match="tr">
  <xsl:apply-templates select="td|th"/>
  <xsl:text>\\</xsl:text>
  <xsl:if test="../@border and not(position()=last())">
    <xsl:text>\hline</xsl:text>
  </xsl:if>
  <xsl:text>
</xsl:text>
</xsl:template>

<xsl:template match="td|th">
    <xsl:variable name="pos" select="position()"/>
    <xsl:text>\begin{minipage}[t]{</xsl:text>
    <xsl:choose>
    <xsl:when test="../../columnspec">
      <xsl:value-of select="../../columnspec/column[$pos]/@width"/>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="1 div last()"/>
    </xsl:otherwise>
    </xsl:choose>
    <xsl:text>\linewidth}</xsl:text>
    <xsl:apply-templates/>
    <xsl:text>\end{minipage}</xsl:text>
    <xsl:if test="not(position()=last())">
      <xsl:text> &amp; </xsl:text>
    </xsl:if>
</xsl:template>

<!--
   This is a horrible hack, but it seems to mostly work.  It does a
   few things:

   1. Transforms references starting in http:// to footnotes with the
      appropriate hyperref macro to make them clickable.  (This needs
      to be expanded to deal with news: and needs to be adjusted to
      deal with "#", which is creating bad links at the moment.)

   2. For intra-document references, constructs the appropriate absolute
      reference using a latex \pageref.  
      This involves applying a simplified version of the
      general URL resolution rules to deal with ../.  It only works for
      one level of subdirectory.

   3. It is also necessary to deal with the fact that index pages
      get references as "/".
-->
<xsl:template match="a">
<xsl:apply-templates/>
<xsl:if test="@href">
<xsl:variable name="relpath" select="document(/*/@metafile)/metafile/relpath" />
<xsl:variable name="path" select="document(/*/@metafile)/metafile/path" />
<xsl:variable name="fileref">
  <xsl:choose>
  <xsl:when test="contains(@href, '.html')">
    <xsl:value-of select="substring-before(@href, '.html')"/>
  </xsl:when>
  <xsl:otherwise>
    <xsl:value-of select="concat(@href, 'index')"/>
  </xsl:otherwise>
  </xsl:choose>
</xsl:variable>
<xsl:choose>

<xsl:when test="starts-with(@href, 'http:') or starts-with(@href, 'news:') or starts-with(@href, 'mailto:')">
  <xsl:if test="not(.=@href)">
    <xsl:text>\footnote{</xsl:text>
      <xsl:text>\href{</xsl:text>
      <xsl:value-of select="@href"/>
      <xsl:text>}{</xsl:text>
    <xsl:call-template name="ltescape">
      <xsl:with-param name="string" select="@href"/>
    </xsl:call-template>
    <xsl:text>}}</xsl:text>
  </xsl:if>
</xsl:when>
<xsl:when test="starts-with(@href, '#')">
<!-- Don't do inter-section references -->
</xsl:when>
<xsl:otherwise>
  <xsl:text> (p.\ \pageref{</xsl:text>
    <xsl:call-template name="replace-string">
      <xsl:with-param name="replace" select="'#'"/>
      <xsl:with-param name="with" select="':'"/>
      <xsl:with-param name="text">
      <xsl:choose>
      <xsl:when test="$relpath='.'">
        <xsl:value-of select="concat('/',$fileref)"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:choose>
        <xsl:when test="starts-with($fileref,'..')">
          <xsl:value-of select="substring-after($fileref,'..')"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="concat($path,$fileref)"/>
        </xsl:otherwise>
        </xsl:choose>
      </xsl:otherwise>
      </xsl:choose>
      </xsl:with-param>
     </xsl:call-template>
  <xsl:text>}) </xsl:text>
</xsl:otherwise>
</xsl:choose>
</xsl:if>
</xsl:template>

<xsl:template match="img">
<xsl:text>[Image not coverted]</xsl:text>
<!--
<xsl:variable name="path" select="document(/*/@metafile)/metafile/path" />
<xsl:text>\includegraphics{</xsl:text>
<xsl:value-of select="concat('.',$path,@src)"/>
<xsl:text>}</xsl:text>
-->
</xsl:template>

</xsl:stylesheet>