<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [
    <!ENTITY nbsp SYSTEM "util/nbsp.xml">
]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!-- document() works relative to the xsl (!) file -->
  <xsl:variable name="basedir" select="'../../'"/>


  <!--                                                    -->
  <!-- <sitemap>                                          -->
  <!-- Process an entire document into an HTML page       -->
  <!--                                                    -->
  <xsl:template match="/sitemap">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <body id="manual-page">

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="top"/>          

<xsl:text>
</xsl:text> <!-- insert line break -->

        <div id="page-content">
          <div id="preamble">        
            <h1>
              <xsl:value-of select="title"/>
            </h1>

<xsl:text>
</xsl:text> <!-- insert line break -->

            <xsl:apply-templates select="summary"/>
          </div> <!-- /preamble -->
          
<xsl:text>
</xsl:text> <!-- insert line break -->

          <xsl:if test="(not($is-chm) and count(category) > 1) or seealso">
            <div id="quickview">
              <xsl:if test="not($is-chm) and count(category) > 1">

                <!-- category index -->
                <ul id="toc">

<xsl:text>
</xsl:text> <!-- insert line break -->

                  <xsl:for-each select="category">
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
                      </li>

<xsl:text>
</xsl:text> <!-- insert line break -->

                    </xsl:if>
                  </xsl:for-each>
                </ul>

<xsl:text>
</xsl:text> <!-- insert line break -->

              </xsl:if>

              <xsl:if test="seealso">
                <h3>
                  <xsl:value-of select="$messages/message[@name='seealso']"/>
                </h3>

<xsl:text>
</xsl:text> <!-- insert line break -->

                <ul class="seealso">
<xsl:text>
</xsl:text> <!-- insert line break -->

                  <xsl:for-each select="seealso">
                    <li>
                      <xsl:apply-templates/>
                    </li>

<xsl:text>
</xsl:text> <!-- insert line break -->

                  </xsl:for-each>
                </ul>

<xsl:text>
</xsl:text> <!-- insert line break -->

              </xsl:if>

	    </div> <!-- /quickview -->

<xsl:text>
</xsl:text> <!-- insert line break -->

          </xsl:if>

          <xsl:apply-templates select="category"/>
        </div> <!-- /page-content -->

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="bottom"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      </body>
    </html>
  </xsl:template>
  

  <!--                                                    -->
  <!-- category/page                                      -->
  <!--                                                    -->
  <xsl:template match="sitemap/category/page">
    <li>
      <xsl:if test="@separate='yes'">
        <xsl:attribute name="class">separate</xsl:attribute>
      </xsl:if>

      <xsl:if test="@href">
        <a href="{@href}">
          <xsl:call-template name="helper.uri.fix">
            <xsl:with-param name="uri" select="@href"/>
          </xsl:call-template>
          <xsl:value-of select="."/>
        </a>
      </xsl:if>
      <xsl:if test="not(@href)">
        <xsl:value-of select="."/>
      </xsl:if>
    </li>

<xsl:text>
</xsl:text> <!-- insert line break -->

  </xsl:template>
  <!-- /category/page -->


  <!--                                                            -->
  <!-- Process a sitemap category                                 -->
  <!--                                                            -->
  <xsl:template match="sitemap/category">

    <xsl:call-template name="toplink"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

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

<xsl:text>
</xsl:text> <!-- insert line break -->

      <!-- category body -->
      <ul>
        <xsl:apply-templates select="page"/>
      </ul>
      
      <xsl:apply-templates select="modulefilelist"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

    </div> <!-- /.section -->
  </xsl:template>
  <!-- /category -->


  <!--                                                    -->
  <!-- category/modulefilelist                            -->
  <!-- insert module list into sitemap                    -->
  <!--                                                    -->
  <xsl:template match="sitemap/category/modulefilelist">

    <!-- create our own translation list first -->
    <xsl:variable name="translist">
      <xsl:text>-</xsl:text>

      <xsl:for-each select="modulefile">
        <xsl:variable name="current" select="document(concat($basedir,'mod/',.))/modulesynopsis" />
   
        <xsl:text> </xsl:text>
        <xsl:value-of select="$current/name"/>
        <xsl:text> </xsl:text>
        <xsl:call-template name="module-translatename">
          <xsl:with-param name="name" select="$current/name"/>
        </xsl:call-template>
        <xsl:text> -</xsl:text>
      </xsl:for-each>
    </xsl:variable>

    <ul>
      <!-- put core and mpm_common on top -->
      <li>
        <a href="mod/core.html">
          <xsl:value-of select="$messages/message[@name='apachecore']"/>
        </a>
      </li>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <li>
        <a href="mod/mpm_common.html">
          <xsl:value-of select="$messages/message[@name='apachempmcommon']"/>
        </a>
      </li>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <xsl:for-each select="modulefile">
      <xsl:sort select="substring-before(substring-after($translist, concat('- ', document(concat($basedir,'mod/',.))/modulesynopsis/name, ' ')), ' -')"/>

        <xsl:variable name="current" select="document(concat($basedir,'mod/',.))/modulesynopsis" />

        <xsl:if test="$current/status='MPM' and $current/name!='mpm_common'">
          <xsl:variable name="name" select="substring-before(substring-after($translist, concat('- ', $current/name, ' ')), ' -')"/>

          <li>
            <a href="mod/{$current/name}.html">
              <xsl:value-of select="$messages/message[@name='apachempm']"/>
              <xsl:text> </xsl:text>
              <xsl:value-of select="$name"/>
            </a>
          </li>

<xsl:text>
</xsl:text> <!-- insert line break -->

        </xsl:if>
      </xsl:for-each>
    </ul>
    <!-- /core, mpm -->

    <ul>
      <xsl:for-each select="modulefile">
      <xsl:sort select="substring-before(substring-after($translist, concat('- ', document(concat($basedir,'mod/',.))/modulesynopsis/name, ' ')), ' -')"/>

        <xsl:variable name="current" select="document(concat($basedir,'mod/',.))/modulesynopsis" />

        <xsl:if test="$current/status!='MPM' and $current/status!='Core' and $current/status!='Obsolete'">
          <li>
            <a href="mod/{$current/name}.html">
              <xsl:value-of select="$messages/message[@name='apachemodule']"/>
              <xsl:text> </xsl:text>
              <xsl:value-of select="$current/name"/>
            </a>
          </li>

<xsl:text>
</xsl:text> <!-- insert line break -->

        </xsl:if>
      </xsl:for-each>
    </ul>
    <!-- /other modules -->

  </xsl:template>
  <!-- /category/modulefilelist -->

</xsl:stylesheet>
