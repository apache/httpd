<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!--                                                    -->
  <!-- <directiveindex>                                   -->
  <!-- Builds the directive index page                    -->
  <!--                                                    -->
  <xsl:template match="directiveindex">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

      <body id="directive-index">
        <xsl:call-template name="top"/>

        <div id="preamble">
          <h1>
            <xsl:value-of select="title"/>
          </h1>

          <xsl:apply-templates select="summary" />

          <!-- letter line -->
          <xsl:if test="letters">
            <p class="letters">
              <xsl:for-each select="letters/*">
                <xsl:variable name="letter" select="."/>

                <!-- check on directives starting with $letter -->
                <xsl:if test="count(document(/*/modulefilelist/modulefile)/modulesynopsis/directivesynopsis[not(@location)][$letter=translate(substring(normalize-space(name),1,1),$lowercase,$uppercase)]) &gt; 0">
                  <xsl:if test="position() > 1"> <!-- assume, we always have directives starting with "A" -->
                    <xsl:text> | </xsl:text>
                  </xsl:if>

                  <a href="#{$letter}">&nbsp;<xsl:value-of select="$letter"/>&nbsp;</a>
                </xsl:if>

              </xsl:for-each>
            </p><xsl:text>
</xsl:text> <!-- insert a line break -->
          </xsl:if>
          <!-- /letter line -->

        </div> <!-- /preamble -->

        <div id="directive-list">
          <ul>
            <xsl:if test="letters">
              <xsl:for-each select="letters/*">
                <xsl:variable name="letter" select="."/>

                <xsl:for-each select="document(/*/modulefilelist/modulefile)/modulesynopsis/directivesynopsis[not(@location)][$letter=translate(substring(normalize-space(name),1,1),$lowercase,$uppercase)]">
                  <xsl:sort select="name"/>

                  <li>
                    <xsl:if test="position()=1">
                      <a name="{$letter}" id="{$letter}" href="{../name}.html#{translate(name,$uppercase,$lowercase)}">
                        <xsl:if test="@type = 'section'">&lt;</xsl:if>
                        <xsl:value-of select="name"/>
                        <xsl:if test="@type = 'section'">&gt;</xsl:if>
                      </a>
                    </xsl:if>

                    <xsl:if test="position() != 1">
		      <a href="{../name}.html#{translate(name,$uppercase,$lowercase)}">
                        <xsl:if test="@type = 'section'">&lt;</xsl:if>
                        <xsl:value-of select="name"/>
                        <xsl:if test="@type = 'section'">&gt;</xsl:if>
                      </a>
                    </xsl:if>
                  </li><xsl:text>
</xsl:text>                                           <!-- insert a line break -->
                </xsl:for-each> <!-- /directives -->
              </xsl:for-each> <!-- /letters -->
            </xsl:if>
            <!-- /if letters -->

              <!-- this branch is only applied, if there's no <letters> specified in directives.xml.
                   you may remove the this branch if you want the letters generally -->
            <xsl:if test="not(letters)">
              <xsl:for-each select="document(/*/modulefilelist/modulefile)/modulesynopsis/directivesynopsis[not(@location)]">
                <xsl:sort select="name"/>

                <li>
                  <a href="{../name}.html#{translate(name,$uppercase,$lowercase)}">
                    <xsl:if test="@type = 'section'">&lt;</xsl:if>
                    <xsl:value-of select="name"/>
                    <xsl:if test="@type = 'section'">&gt;</xsl:if>
                  </a>
                </li><xsl:text>
</xsl:text>                                           <!-- insert a line break -->
              </xsl:for-each>
            </xsl:if>
            <!-- /no letters -->

          </ul>
        </div> <!-- /directive-index -->

        <xsl:call-template name="bottom"/>
      </body>
    </html>
  </xsl:template> 

</xsl:stylesheet>
