<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

<!-- Constants used for case translation -->
<xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'" />
<xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

<!-- ==================================================================== -->
<!-- Process a documentation section                                      -->
<!-- ==================================================================== -->
<xsl:template match="section">
<xsl:apply-templates/>
</xsl:template>

<xsl:template match="section/title">
<xsl:text>\subsection*{</xsl:text>
<xsl:apply-templates/>
<xsl:text>}</xsl:text><xsl:call-template name="label"/>
<xsl:text>
</xsl:text>
</xsl:template>

<xsl:template match="section/section/title">
<xsl:text>\subsubsection*{</xsl:text>
<xsl:apply-templates/>
<xsl:text>}</xsl:text><xsl:call-template name="label"/>
<xsl:text>
</xsl:text>
</xsl:template>

<xsl:template match="section/section/section/title">
<xsl:text>\subsubsection*{</xsl:text>
<xsl:apply-templates/>
<xsl:text>}</xsl:text><xsl:call-template name="label"/>
<xsl:text>
</xsl:text>
</xsl:template>

<xsl:template match="note/title"></xsl:template>
<xsl:template match="example/title"></xsl:template>

<xsl:template name="label">
<xsl:if test="../@id">
<xsl:variable name="metafile" select="document(/*/@metafile)/metafile" />
<xsl:text>\label{</xsl:text><xsl:value-of 
select="$metafile/path"/><xsl:value-of 
select="$metafile/basename"/>
<xsl:text>:</xsl:text>
<xsl:value-of select="../@id"/>
<xsl:text>}</xsl:text>
</xsl:if>
</xsl:template>


<!-- ==================================================================== -->
<!-- <example>                                                            -->
<!-- ==================================================================== -->

<xsl:template match="example">
<xsl:text>\par\medskip\begin{center}</xsl:text>
<xsl:if test="not(pre)"><xsl:text>\fbox{</xsl:text></xsl:if>
<xsl:text>\begin{minipage}{.8\textwidth}\begin{flushleft}</xsl:text>
<xsl:apply-templates select="title" mode="print" />
<xsl:if test="not(pre)"><xsl:text>{\ttfamily </xsl:text></xsl:if>
<xsl:text>\noindent </xsl:text><xsl:apply-templates/>
<xsl:if test="not(pre)"><xsl:text>}</xsl:text></xsl:if>
<xsl:text>\end{flushleft}\end{minipage}</xsl:text>
<xsl:if test="not(pre)"><xsl:text>}</xsl:text></xsl:if>
<xsl:text>\end{center}\par\medskip</xsl:text>
</xsl:template>

<xsl:template match="example/title" mode="print">
<xsl:text>\textbf{</xsl:text>
    <xsl:apply-templates/>
<xsl:text>}\\ </xsl:text>
</xsl:template>


<!-- ==================================================================== -->
<!-- indentations                                                         -->
<!-- ==================================================================== -->
<xsl:template match="indent">
<xsl:text>\hfill\begin{minipage}{.9\textwidth}{\texttt </xsl:text>
<xsl:apply-templates/>
<xsl:text>}\end{minipage}</xsl:text>
</xsl:template>

<!-- ==================================================================== -->
<!-- <note>                                                               -->
<!-- ==================================================================== -->
<xsl:template match="note">
<xsl:text>\par\medskip
{\Huge $\Longrightarrow$}\begin{minipage}[t]{.8\textwidth}
\noindent </xsl:text>
<xsl:apply-templates select="title" mode="print" />
<xsl:apply-templates/>
<xsl:text>\end{minipage}\par\medskip</xsl:text>
</xsl:template>

<xsl:template match="note/title" mode="print">
<xsl:text>\textbf{</xsl:text>
    <xsl:apply-templates/>
<xsl:text>} \\
\noindent </xsl:text>
</xsl:template>


<!-- ==================================================================== -->
<!-- <directive>                                                          -->
<!-- Inserts link to another directive, which might be in another module. -->
<!-- References are converted into lower case.                            -->
<!-- ==================================================================== -->
<xsl:template match="directive" name="directive">
<xsl:text>\textsc{</xsl:text>
        <xsl:if test="@type='section'">\textless{}</xsl:if>
        <xsl:apply-templates/>
        <xsl:if test="@type='section'">\textgreater{}</xsl:if>
<xsl:text>}</xsl:text>
</xsl:template>
<!-- /directive -->

<!-- ==================================================================== -->
<!-- <module>                                                             -->
<!-- Inserts a link to refereed module                                    -->
<!-- ==================================================================== -->
<xsl:template match="module" name="module">
<xsl:text>\textsc{</xsl:text>
    <xsl:apply-templates/>
<xsl:text>}</xsl:text>
</xsl:template>
<!-- /module -->



<!-- ==================================================================== -->
<!-- <related>                                                            -->
<!-- ==================================================================== -->
<xsl:template match="related">
<xsl:text>
\fbox{\begin{tabular}{rr}
\begin{minipage}[t]{.4\linewidth}
\textbf{</xsl:text>
<xsl:value-of select="$messages/message[@name='relatedmodules']" />
<xsl:text>} \\
</xsl:text>
<xsl:for-each select="modulelist/module">
<xsl:call-template name="module"/>
<xsl:text> \\
</xsl:text>
</xsl:for-each>
<xsl:text>
\end{minipage} &amp; 
\begin{minipage}[t]{.4\linewidth}
\textbf{</xsl:text>
<xsl:value-of select="$messages/message[@name='relateddirectives']" />
<xsl:text>} \\
</xsl:text>
<xsl:for-each select="directivelist/directive">
<xsl:call-template name="directive"/>
<xsl:text> \\
</xsl:text>
</xsl:for-each>
<xsl:text>
\end{minipage}
\end{tabular}}
\medskip
</xsl:text>
</xsl:template>

</xsl:stylesheet>