<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!-- three columns, select were the particular categories shall be
       placed in. (order is irrelevant, they're placed in document order) -->

  <xsl:variable name="indexpage-column1" select="'
    release
    manual
  '"/>

  <xsl:variable name="indexpage-column2" select="'
    usersguide
  '"/>

  <xsl:variable name="indexpage-column3" select="'
    howto
    platform
    other
  '"/>

  <!--                                                    -->
  <!-- <indexpage>                                        -->
  <!-- Process an entire document into an HTML page       -->
  <!--                                                    -->
  <xsl:template match="/indexpage">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <body id="index-page">

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="top"/>          

<xsl:text>
</xsl:text> <!-- insert line break -->

        <div id="page-content">
          <h1>
            <xsl:value-of select="title"/>
          </h1>

<xsl:text>
</xsl:text> <!-- insert line break -->

          <form method="post" action="http://search.apache.org/"><p>
            <input type="hidden" name="what" value="httpd.apache.org" />
            <input type="hidden" name="results" value="20" />
            <input type="hidden" name="version" value="2" />
            <input type="text" name="keyword" size="20" />
            <xsl:text> </xsl:text>
            <input type="submit" value="{$messages/message[@name='search']}" />
          </p></form>

<xsl:text>
</xsl:text> <!-- insert line break -->

          <table id="indextable">
            <tr>
              <td class="col1">
                <xsl:apply-templates
                    select="category[contains($indexpage-column1, @id)]"/>
              </td>
              <td>
                <xsl:apply-templates
                    select="category[contains($indexpage-column2, @id)]"/>
              </td>
              <td class="col3">
                <xsl:apply-templates
                    select="category[contains($indexpage-column3, @id)]"/>
              </td>
            </tr>
          </table>
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
  <xsl:template match="indexpage/category/page">
    <li>
      <xsl:if test="@separate='yes'">
        <xsl:attribute name="class">separate</xsl:attribute>
      </xsl:if>

      <xsl:if test="@href">
        <a href="{@href}">
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
  <xsl:template match="indexpage/category">

    <div class="category">

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
      
<xsl:text>
</xsl:text> <!-- insert line break -->

    </div> <!-- /.section -->
  </xsl:template>
  <!-- /category -->

</xsl:stylesheet>

