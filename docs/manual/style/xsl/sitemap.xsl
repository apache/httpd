<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!-- document() works relative to the xsl (!) file -->
  <xsl:variable name="basedir" select="'../../'"/>


  <!--                                                    -->
  <!-- <sitemap>                                          -->
  <!-- Process an entire document into an HTML page       -->
  <!--                                                    -->
  <xsl:template match="sitemap">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

      <body id="manual-page">
        <xsl:call-template name="top"/>          

        <div id="page-content">
          <div id="preamble">        
            <h1>
              <xsl:value-of select="title"/>
            </h1>

            <xsl:apply-templates select="summary"/>
          </div> <!-- /preamble -->
          
          <xsl:if test="count(category) > 1 or seealso">
            <div id="quickview">
              <xsl:if test="count(category) > 1">

                <!-- category index -->
                <ul id="toc">
                  <xsl:for-each select="category">
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
                      </li>
                    </xsl:if>
                  </xsl:for-each>
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
          </xsl:if>

          <xsl:apply-templates select="category"/>
        </div> <!-- /page-content -->

        <xsl:call-template name="bottom"/>
      </body>
    </html>
  </xsl:template>
  

  <!--                                                    -->
  <!-- category/page                                      -->
  <!--                                                    -->
  <xsl:template match="category/page">
    <xsl:variable name="link">
      <xsl:if test="@href">
        <a href="{@href}">
          <xsl:value-of select="."/>
        </a>
      </xsl:if>
      <xsl:if test="not(@href)">
        <xsl:value-of select="."/>
      </xsl:if>
    </xsl:variable>

    <xsl:if test="@separate='yes'">
      <li class="separate">
        <xsl:copy-of select="$link"/>
      </li>
    </xsl:if>

    <xsl:if test="@separate='no'">
      <li>
        <xsl:copy-of select="$link"/>
      </li>
    </xsl:if>
  </xsl:template>
  <!-- /category/page -->


  <!--                                                            -->
  <!-- Process a sitemap category                                 -->
  <!--                                                            -->
  <xsl:template match="category">

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

      <!-- category body -->
      <ul>
        <xsl:apply-templates select="page"/>
      </ul>
      
      <xsl:apply-templates select="modulefilelist"/>

    </div> <!-- /.section -->
  </xsl:template>
  <!-- /category -->


  <!--                                                    -->
  <!-- category/modulefilelist                            -->
  <!-- insert module list into sitemap                    -->
  <!--                                                    -->
  <xsl:template match="category/modulefilelist">
    <ul>
      <xsl:for-each select="modulefile">
        <xsl:sort select="document(concat($basedir,'mod/',.))/modulesynopsis/name"/>
        <xsl:variable name="current" select="document(concat($basedir,'mod/',.))/modulesynopsis" />

        <xsl:if test="$current/status='MPM' or $current/status='Core'">
          <xsl:variable name="name"><xsl:choose>
            <xsl:when test="starts-with($current/name,'mpm_')">
              <xsl:value-of select="substring($current/name,5)"/>
            </xsl:when>

            <xsl:otherwise>
              <xsl:value-of select="$current/name"/>
            </xsl:otherwise>
          </xsl:choose></xsl:variable>

          <li>
            <a href="mod/{$current/name}.html"><xsl:choose>
              <xsl:when test="$name='core'">
                <xsl:value-of select="$messages/message[@name='apachecore']"/>
              </xsl:when>

              <xsl:when test="$name='common'">
                <xsl:value-of select="$messages/message[@name='apachempmcommon']"/>
              </xsl:when>
                
              <xsl:otherwise>
                <xsl:value-of select="$messages/message[@name='apachempm']"/>
                <xsl:text> </xsl:text>
                <xsl:value-of select="$name"/>
              </xsl:otherwise></xsl:choose>
            </a>
          </li>
        </xsl:if>
      </xsl:for-each>
      <!-- /core,mpm -->

      <xsl:for-each select="modulefile">
        <xsl:sort select="document(concat($basedir,'mod/',.))/modulesynopsis/name"/>
        <xsl:variable name="current" select="document(concat($basedir,'mod/',.))/modulesynopsis" />

        <xsl:if test="$current/status!='MPM' and $current/status!='Core'">
          <li>
            <a href="mod/{$current/name}.html">
              <xsl:value-of select="$messages/message[@name='apachemodule']"/>
              <xsl:text> </xsl:text>
              <xsl:value-of select="$current/name"/>
            </a>
          </li>
        </xsl:if>
      </xsl:for-each>
      <!-- /other modules -->

    </ul>
  </xsl:template>
  <!-- /category/modulefilelist -->

</xsl:stylesheet>
