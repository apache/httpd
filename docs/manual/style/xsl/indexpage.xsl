<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [
    <!ENTITY nbsp SYSTEM "util/nbsp.xml">
]>
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

          <form action="http://www.google.com/search" method="get">
          <xsl:if test="$ext-target = '1'">
            <xsl:attribute name="target">_blank</xsl:attribute>
          </xsl:if>
          
          <p>
          <!-- search google: -->
          <!-- with all of the words -->
          <input type="text" value="" name="as_q" />
          <xsl:text> </xsl:text>
          <input type="submit" value="{$messages/message[@name='search']}" />

          <!-- the specified number of results -->
          <input type="hidden" name="num" value="10" />

          <!-- the current displayed language -->
          <input type="hidden" name="hl" value="{$messages/@lang}" />

          <!-- the current document encoding for input (?) -->
          <input type="hidden" name="ie" value="{$output-encoding}" />

          <!-- (submit the original button and name) -->
          <input type="hidden" name="btnG" value="Google Search" />

          <!-- including the exact phrase "Apache 2.0" -->
          <input type="hidden" value="Apache 2.0" name="as_epq" />

          <!-- with at least one of the words (none) -->
          <input type="hidden" value="" name="as_oq" />

          <!-- without the phrase "List-Post" (to exclude the mail archives) -->
          <input type="hidden" value="&quot;List-Post&quot;" name="as_eq" />

          <!-- return results written in (any) language -->
          <input type="hidden" name="lr" value="" />

          <!-- and any format -->
          <input type="hidden" name="as_ft" value="i" />
          <input type="hidden" name="as_filetype" value="" />

          <!-- updated anytime -->
          <input type="hidden" name="as_qdr" value="all" />

          <!-- where the result appears anywhere in the document -->
          <input type="hidden" name="as_occt" value="any" />

          <!-- only from httpd.apache.org -->
          <input type="hidden" name="as_dt" value="i" />
          <input type="hidden" name="as_sitesearch" value="httpd.apache.org" />

          <!-- turn off "safe" mode -->
          <input type="hidden" name="safe" value="off" />
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

