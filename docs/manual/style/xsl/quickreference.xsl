<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!--                                                    -->
  <!-- <quickreference>                                   -->
  <!-- Builds the directive quickreference page           -->
  <!--                                                    -->
  <xsl:template match="quickreference">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <body id="directive-index">

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="top"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

        <div id="preamble">
          <h1>
            <xsl:value-of select="title"/>
          </h1>

<xsl:text>
</xsl:text> <!-- insert line break -->

          <xsl:apply-templates select="summary" />
        </div> <!-- /preamble -->

<xsl:text>
</xsl:text> <!-- insert a line break -->

        <div id="directive-ref">

         <xsl:variable name="directives" select="document(sitemap/category[@id='modules']/modulefilelist/modulefile)/modulesynopsis[status!='Obsolete']/directivesynopsis[not(@location)]"/>

          <!-- first collect the start letters -->
          <xsl:variable name="start-letters">
            <xsl:call-template name="directive-startletters">
              <xsl:with-param name="directives" select="$directives"/>
            </xsl:call-template>
          </xsl:variable>

          <table id="legend">

<xsl:text>
</xsl:text> <!-- insert line break -->

            <tr>
              <td class="letters"><span>
                <xsl:call-template name="letter-bar">
                  <xsl:with-param name="letters" select="$start-letters"/>
                  <xsl:with-param name="first" select="true()"/>
                </xsl:call-template>
              </span></td>

<xsl:text>
</xsl:text> <!-- insert a line break -->

              <td>
                <xsl:apply-templates select="legend/table[position()=1]"/>
              </td>

<xsl:text>
</xsl:text> <!-- insert line break -->

              <td>
                <xsl:apply-templates select="legend/table[position()=2]"/>
              </td>
            </tr>

<xsl:text>
</xsl:text> <!-- insert line break -->

          </table>

<xsl:text>
</xsl:text> <!-- insert a line break -->

          <table class="qref">

<xsl:text>
</xsl:text> <!-- insert line break -->

            <xsl:call-template name="reference-of-letter">
              <xsl:with-param name="letters-todo" select="$start-letters"/>
              <xsl:with-param name="offset" select="number(0)"/>
              <xsl:with-param name="directives" select="$directives"/>
            </xsl:call-template>
          </table>

        </div> <!-- /directive-ref -->

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="bottom"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      </body>
    </html>
  </xsl:template>


  <!--                                                     -->
  <!-- the working horse. builds rows of all directives    -->
  <!-- starting with one letter                            -->
  <!-- when done, it calls itself to catch the next letter -->
  <!--                                                     -->
  <xsl:template name="reference-of-letter">
  <xsl:param name="letters-todo"/>
  <xsl:param name="offset"/>
  <xsl:param name="directives"/>

    <xsl:variable name="letter" select="substring($letters-todo,1,1)"/>

    <xsl:for-each select="$directives[$letter=translate(substring(normalize-space(name),1,1),$lowercase,$uppercase)]">
    <xsl:sort select="name"/>

      <tr>
        <xsl:if test="position() mod 2 = $offset">
          <xsl:attribute name="class">odd</xsl:attribute>
        </xsl:if>

        <td>
          <a href="{../name}.html#{translate(name,$uppercase,$lowercase)}">
            <xsl:if test="position()=1">
              <xsl:attribute name="id"><xsl:value-of select="$letter"/></xsl:attribute>
              <xsl:attribute name="name"><xsl:value-of select="$letter"/></xsl:attribute>
            </xsl:if>

            <xsl:apply-templates select="syntax"/>
          </a>
        </td>

        <td>
          <xsl:variable name="default">
            <xsl:choose>
              <xsl:when test="count(default[count(br) &gt; 0]) &gt; 0">
                <xsl:value-of select="default/child::node()[count(preceding-sibling::*) = 0]"/>
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="default"/>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:variable>

          <xsl:value-of select="substring(substring-after(concat($default,' '),name),1,20)"/>
          <xsl:if test="string-length(substring-after(concat($default,' '),name)) &gt; 20
                     or count(default[count(br) &gt; 0]) &gt; 0">
            <xsl:text> +</xsl:text>
          </xsl:if>
        </td>

        <td>
          <xsl:if test="contextlist/context[normalize-space(.)='server config']">s</xsl:if>
          <xsl:if test="contextlist/context[normalize-space(.)='virtual host']">v</xsl:if>
          <xsl:if test="contextlist/context[normalize-space(.)='directory']">d</xsl:if>
          <xsl:if test="contextlist/context[normalize-space(.)='.htaccess']">h</xsl:if>
        </td>

        <td>
          <xsl:choose>
            <xsl:when test="../status='Base'">B</xsl:when>
            <xsl:when test="../status='MPM'">M</xsl:when>
            <xsl:when test="../status='Core'">C</xsl:when>
            <xsl:when test="../status='Extension'">E</xsl:when>
            <xsl:when test="../status='Experimental'">X</xsl:when>
          </xsl:choose>
        </td>
      </tr>

      <tr>
        <xsl:if test="position() mod 2 = $offset">
          <xsl:attribute name="class">odd</xsl:attribute>
        </xsl:if>

        <td colspan="4" class="descr"><xsl:choose>
          <xsl:when test="string-length(normalize-space(description)) &gt; 0">
            <xsl:apply-templates select="description"/>
          </xsl:when>

          <xsl:otherwise>
            <xsl:text>-</xsl:text>
          </xsl:otherwise></xsl:choose>
        </td>
      </tr>

<xsl:text>
</xsl:text> <!-- insert a line break -->

    </xsl:for-each> <!-- /directives -->

    <!-- call next letter, if there is -->
    <xsl:if test="string-length($letters-todo) &gt; 1">
      <xsl:call-template name="reference-of-letter">
        <xsl:with-param name="letters-todo" select="substring($letters-todo,2)"/>
        <xsl:with-param name="offset" select="(count($directives[$letter=translate(substring(normalize-space(name),1,1),$lowercase,$uppercase)]) + $offset) mod 2"/>
        <xsl:with-param name="directives" select="$directives"/>
      </xsl:call-template>
    </xsl:if>

  </xsl:template>
  <!-- /reference-of-letter -->

</xsl:stylesheet>