<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [
    <!ENTITY nbsp SYSTEM "util/nbsp.xml">
]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!--                                                    -->
  <!-- <manualpage>                                       -->
  <!-- Process an entire document into an HTML page       -->
  <!--                                                    -->
  <xsl:template match="manualpage">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <body id="manual-page">
        <!-- unsqueeze if there's no sidebar -->
        <xsl:if test="not(count(section) > 1 or seealso)">
          <xsl:attribute name="class">no-sidebar</xsl:attribute>
        </xsl:if>

        <xsl:call-template name="top"/>          

        <div id="page-content">
          <div id="preamble">        
            <h1>
              <xsl:value-of select="title"/>
            </h1>

            <xsl:apply-templates select="summary"/>
          </div> <!-- /preamble -->
          
<xsl:text>
</xsl:text> <!-- insert line break -->

          <xsl:if test="count(section) > 1 or seealso">
            <div id="quickview">
              <xsl:if test="count(section) > 1">
                <ul id="toc">
                  <xsl:apply-templates select="section" mode="index"/>
                </ul>
              </xsl:if>

              <xsl:if test="seealso">
                <h3>
                  <xsl:value-of select="$messages/message[@name='seealso']"/>
                </h3>
                <ul class="seealso">
                  <xsl:for-each select="seealso">
                    <li>
                      <xsl:apply-templates/>
                    </li>
                  </xsl:for-each>
                </ul>
              </xsl:if>

	    </div> <!-- /quickview -->

<xsl:text>
</xsl:text> <!-- insert line break -->

          </xsl:if>

          <xsl:apply-templates select="section"/>
        </div> <!-- /page-content -->

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="bottom"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      </body>
    </html>
  </xsl:template>

</xsl:stylesheet>
