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
  <xsl:template match="faq">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <body id="manual-page">
        <!-- unsqueeze if there's no sidebar -->
        <xsl:if test="not(count(section) > 1 or (/faq/@all-in-one = 'yes') or seealso)">
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

          <xsl:if test="(not($is-chm) and (count(section) > 1 or (/faq/@all-in-one = 'yes'))) or seealso">
            <div id="quickview">
              <xsl:if test="not($is-chm)">
              <xsl:if test="count(section) > 1">
                <ul id="toc">
                  <xsl:apply-templates select="section" mode="index"/>
                </ul>
              </xsl:if>

              <xsl:if test="/faq/@all-in-one = 'yes'">
                <ul id="toc">
                  <li>
                    <img src="{$path}/images/down.gif" alt="" />
                    <xsl:text> </xsl:text>
                    <a href="#topics">
                      <xsl:value-of select="$messages/message[@name='topics']"/>
                    </a>
                  </li>

<xsl:text>
</xsl:text>

                  <xsl:apply-templates select="categories/categoryfile" mode="toc"/>
                </ul>
              </xsl:if>
              </xsl:if> <!-- chm -->

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

          <!-- either one ... -->
          <xsl:apply-templates select="section"/>
          <!-- ... or the other is allowed -->
          <xsl:apply-templates select="categories"/>
        </div> <!-- /page-content -->

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="bottom"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      </body>
    </html>
  </xsl:template>

  <xsl:template match="categories">

    <xsl:call-template name="toplink"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

    <div class="section">

<xsl:text>
</xsl:text> <!-- insert line break -->

      <!-- Section heading -->
      <h2>
        <a name="topics" id="topics">
          <xsl:value-of select="$messages/message[@name='topics']"/>
        </a>
      </h2>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <dl>
        <xsl:apply-templates select="categoryfile" mode="index"/>
      </dl>
    </div> <!-- /.section -->

    <xsl:if test="/faq/@all-in-one = 'yes'">
      <xsl:apply-templates select="categoryfile" mode="suckin"/>
    </xsl:if>

  </xsl:template>

  <xsl:template match="categories/categoryfile" mode="index">
    <xsl:variable name="current" select="document(.)/faq" />

    <dt>
      <a>
        <xsl:attribute name="href"><xsl:choose>
          <xsl:when test="/faq/@all-in-one = 'yes'">
            <xsl:value-of select="concat('#', $current/section/@id)" />
          </xsl:when>

          <xsl:otherwise>
            <xsl:value-of select="concat(document($current/@metafile)/metafile/basename, '.html')" />
          </xsl:otherwise></xsl:choose>
        </xsl:attribute>

        <xsl:value-of select="$current/section/title" />
      </a>
    </dt>
    <dd>
      <xsl:apply-templates select="$current/description/node()" />
    </dd>

<xsl:text>
</xsl:text>

  </xsl:template>

  <xsl:template match="categories/categoryfile" mode="toc">
    <xsl:variable name="current" select="document(.)/faq" />

    <li>
      <img src="{$path}/images/down.gif" alt="" />
      <xsl:text> </xsl:text>
      <a href="#{$current/section/@id}">
        <xsl:value-of select="$current/section/title" />
      </a>
    </li>

<xsl:text>
</xsl:text>

  </xsl:template>

  <xsl:template match="categories/categoryfile" mode="suckin">
    <xsl:apply-templates select="document(.)/faq/section" />
  </xsl:template>

</xsl:stylesheet>
