<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

<xsl:template match="manualpage">
<xsl:variable name="metafile" select="document(/*/@metafile)/metafile" />

<xsl:text>\section{</xsl:text><xsl:apply-templates select="title"/>
<xsl:text>}</xsl:text>
<xsl:text>\label{</xsl:text><xsl:value-of 
select="$metafile/path"/><xsl:value-of 
select="$metafile/basename"/>
<xsl:text>}
</xsl:text>
<xsl:apply-templates select="summary"/>


   <xsl:if test="seealso">
   <xsl:text>\medskip\noindent\textbf{</xsl:text>
   <xsl:value-of select="$messages/message[@name='seealso']" />
   <xsl:text>}
   \begin{itemize}</xsl:text>
   <xsl:for-each select="seealso">
     <xsl:text>\item </xsl:text><xsl:apply-templates />
   </xsl:for-each>
   \end{itemize}
   </xsl:if>

<xsl:apply-templates select="section"/>
</xsl:template>

</xsl:stylesheet>