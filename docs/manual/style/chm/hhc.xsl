<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE xsl:stylesheet [
  <!ENTITY lf SYSTEM "../xsl/util/lf.xml">
  <!ENTITY tab SYSTEM "../xsl/util/tab.xml">
]>

<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<!--
    XXX: WARNING! Do not touch anything, especially the whitespaces [1] unless
    you know, what you're doing. The HTML help compiler parses the TOC file
    not really as html instead of line by line and takes care of whitespace
    indentations etc.

    [1] Covered by the &lf; and &tab; entities.

    You have been warned.
-->

<!-- documents not converted (yet?). -->
<xsl:variable name="not-existing">
  developer/API.xml

  programs/ab.xml
  programs/apxs.xml
  programs/dbmmanage.xml
  programs/htdigest.xml
  programs/htpasswd.xml
  programs/logresolve.xml
  programs/rotatelogs.xml
  programs/suexec.xml
  programs/other.xml
</xsl:variable>

<!-- Constants used for case translation -->
<xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'" />
<xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

<!-- document() works relative to the xsl (!) file -->
<xsl:variable name="basedir" select="'../../'"/>

<!-- icons -->
<xsl:variable name="icon.document" select="'11'" />
<xsl:variable name="icon.document.not-translated" select="'12'" />
<xsl:variable name="icon.section" select="'35'" />
<xsl:variable name="icon.directive" select="'41'" />
<xsl:variable name="icon.commondirective" select="'19'" />

<!-- for module-translatename -->
<xsl:include href="../xsl/util/modtrans.xsl"/>

<!--                                                    -->
<!-- <sitemap>                                          -->
<!-- Process an entire document into an HTML page       -->
<!--                                                    -->
<xsl:template match="/sitemap">
<xsl:text>&lt;html&gt;&lt;head&gt;</xsl:text>
<xsl:text>&lt;title&gt;TOC - Apache HTTP Server Documentation&lt;/title&gt;</xsl:text>
<xsl:text>&lt;/head&gt;</xsl:text>&lf;

<xsl:text>&lt;body&gt;</xsl:text>&lf;

<!-- toc properties first -->
<xsl:text>
&lt;object type="text/site properties"&gt;
&#9;&lt;param name="Window Styles" value="0x800027"&gt;
&#9;&lt;param name="Font" value="</xsl:text>
    <xsl:value-of select="$toc-font" />
<xsl:text>"&gt;</xsl:text>&lf;
<xsl:text>&lt;/object&gt;</xsl:text>&lf;

<xsl:text>&lt;ul&gt;</xsl:text>&lf;

<!-- index page on top. -->
<xsl:text>&lt;li&gt;&lt;object type="text/sitemap"&gt;</xsl:text>&lf;&tab;&tab;

  <xsl:text>&lt;param name="Name" value="</xsl:text>
    <xsl:call-template name="filter.attval">
      <xsl:with-param name="text" select="$messages/message[@name='apachehttpserver']" />
    </xsl:call-template>
  <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;

  <xsl:text>&lt;param name="Local" value="</xsl:text>
      <xsl:value-of select="'index.html'" />
  <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;

  <xsl:text>&lt;param name="ImageNumber" value="</xsl:text>
    <xsl:choose>
      <xsl:when test="$messages/@lang='en' or (document(document(concat($basedir, 'index.xml'))/*/@metafile)/metafile/variants/variant[.=$messages/@lang and not(@htmlonly='yes')])">
        <xsl:value-of select="$icon.document" />
      </xsl:when>

      <xsl:otherwise>
        <xsl:value-of select="$icon.document.not-translated" />
      </xsl:otherwise>
    </xsl:choose>
  <xsl:text>"&gt;</xsl:text>&lf;&tab;

  <xsl:text>&lt;/object&gt;&lt;/li&gt;</xsl:text>&lf;

<xsl:for-each select="category">

<xsl:text>&lt;li&gt;&lt;object type="text/sitemap"&gt;</xsl:text>&lf;&tab;&tab;

  <xsl:text>&lt;param name="Name" value="</xsl:text>
    <xsl:call-template name="filter.attval">
      <xsl:with-param name="text" select="normalize-space(title)" />
    </xsl:call-template>
  <xsl:text>"&gt;</xsl:text>&lf;&tab;
    <xsl:text>&lt;/object&gt;</xsl:text>&lf;&tab;

    <xsl:text>&lt;ul&gt;</xsl:text>&lf;&tab;

      <xsl:for-each select="page">

        <xsl:variable name="local"><xsl:choose>
          <xsl:when test="not(@href)">
            <xsl:text>sitemap.html</xsl:text>
          </xsl:when>

          <xsl:when test="contains(@href, '#') and substring(@href, string-length(substring-before(@href, '#')), 1) = '/'">
            <xsl:value-of select="substring-before(@href, '#')" />
            <xsl:text>index.html</xsl:text>
          </xsl:when>

          <xsl:when test="substring(@href,string-length(@href),1) = '/'">
            <xsl:value-of select="@href"/>
            <xsl:text>index.html</xsl:text>
          </xsl:when>

          <xsl:otherwise><xsl:value-of select="@href"/></xsl:otherwise></xsl:choose>
        </xsl:variable>

        <xsl:variable name="xmlfile-en" select="concat(substring-before($local, '.html'), '.xml')"/>
        <xsl:variable name="xmlfile-exists" select="boolean(not(contains(concat(' ', normalize-space($not-existing), ' '), concat(' ', $xmlfile-en, ' '))))"/>

        <xsl:text>&lt;li&gt;&lt;object type="text/sitemap"&gt;</xsl:text>&lf;&tab;&tab;

          <xsl:text>&lt;param name="Name" value="</xsl:text>
            <xsl:call-template name="filter.attval">
              <xsl:with-param name="text">
                <xsl:if test="@href">
                  <xsl:value-of select="normalize-space(.)" />
                </xsl:if>
                <xsl:if test="not(@href)">
                  <xsl:value-of select="normalize-space($messages/message[@name='sitemap'])" />
                </xsl:if>
              </xsl:with-param>
            </xsl:call-template>
          <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;

          <xsl:text>&lt;param name="Local" value="</xsl:text>
            <xsl:choose>
              <xsl:when test="not(@href)">
                <xsl:text>sitemap.html</xsl:text>
              </xsl:when>

              <xsl:when test="contains(@href, '#') and substring(@href, string-length(substring-before(@href, '#')), 1) = '/'">
                <xsl:value-of select="substring-before(@href, '#')" />
                <xsl:text>index.html#</xsl:text>
                <xsl:value-of select="substring-after(@href, '#')" />
              </xsl:when>

              <xsl:when test="substring(@href,string-length(@href),1) = '/'">
                <xsl:value-of select="@href"/>
                <xsl:text>index.html</xsl:text>
              </xsl:when>

              <xsl:otherwise><xsl:value-of select="@href"/></xsl:otherwise>
            </xsl:choose>
          <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;

          <xsl:text>&lt;param name="ImageNumber" value="</xsl:text>
            <xsl:choose>
              <xsl:when test="$messages/@lang='en' or ($xmlfile-exists and document(document(concat($basedir, $xmlfile-en))/*/@metafile)/metafile/variants/variant[.=$messages/@lang and not(@htmlonly='yes')])">
                <xsl:value-of select="$icon.document" />
              </xsl:when>

              <xsl:otherwise>
                <xsl:value-of select="$icon.document.not-translated" />
              </xsl:otherwise>
            </xsl:choose>
          <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;
          <xsl:text>&lt;/object&gt;</xsl:text>

          <xsl:if test="$xmlfile-exists">
            <xsl:variable name="metafile" select="document(document(concat($basedir, $xmlfile-en))/*/@metafile)/metafile" />
            <xsl:if test="not($metafile/variants/variant[.=$messages/@lang] and $metafile/variants/variant[.=$messages/@lang]/@htmlonly = 'yes')">
              <xsl:variable name="xmlfile"><xsl:choose>
                <xsl:when test="$metafile/variants/variant[.=$messages/@lang]">
                    <xsl:value-of select="concat($basedir, substring-before($local, '.html'), $xml-ext)" />
                </xsl:when>
                <xsl:otherwise>
                    <xsl:value-of select="concat($basedir, substring-before($local, '.html'), '.xml')" />
                </xsl:otherwise></xsl:choose>
              </xsl:variable>

              <xsl:variable name="current" select="document($xmlfile)" />
              <xsl:if test="count($current/*/*[local-name()='section' or local-name()='category']) > 1">&lf;&tab;&tab;&tab;

                <xsl:text>&lt;ul&gt;</xsl:text>&lf;&tab;&tab;&tab;

                  <xsl:for-each select="$current/*/*[local-name()='section' or local-name()='category']">
                    <xsl:text>&lt;li&gt;&lt;object type="text/sitemap"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;
                      <xsl:text>&lt;param name="Name" value="</xsl:text>
                        <xsl:call-template name="filter.attval">
                          <xsl:with-param name="text" select="normalize-space(title)" />
                        </xsl:call-template>
                      <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;

                      <xsl:if test="@id">
                        <xsl:text>&lt;param name="Local" value="</xsl:text>
                            <xsl:value-of select="$local" />
                            <xsl:text>#</xsl:text>
                            <xsl:value-of select="@id" />
                        <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;
                      </xsl:if>

                      <xsl:text>&lt;param name="ImageNumber" value="</xsl:text>
                          <xsl:if test="@id"><xsl:value-of select="$icon.section" /></xsl:if>
                          <xsl:if test="not(@id)">9</xsl:if> <!-- "?" -->
                      <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;
                    <xsl:text>&lt;/object&gt;&lt;/li&gt;</xsl:text>&lf;&tab;&tab;
                  </xsl:for-each>
                <xsl:text>&lt;/ul&gt;</xsl:text>&lf;&tab;
              </xsl:if> <!-- count() > 1 -->
            </xsl:if> <!-- $xml-ext exists -->
          </xsl:if> <!-- xml exists -->
        <xsl:text>&lt;/li&gt;</xsl:text>&lf;&tab;
      </xsl:for-each> <!-- / page -->

      <xsl:apply-templates select="modulefilelist"/>
    <xsl:text>&lt;/ul&gt;</xsl:text>&lf;
  <xsl:text>&lt;/li&gt;</xsl:text>&lf;&tab;
</xsl:for-each>&lf;

<xsl:text>&lt;/ul&gt;</xsl:text>&lf;

<xsl:text>&lt;/body&gt;&lt;/html&gt;</xsl:text>&lf;

</xsl:template>
  
<xsl:template match="category/modulefilelist">

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

  <!-- put core and mpm_common on top -->
  <xsl:call-template name="toc-entry.mpm">
    <xsl:with-param name="current" select="document(concat($basedir, 'mod/', modulefile[starts-with(.,'core.xml')]/text()))/modulesynopsis"/>
    <xsl:with-param name="name" select="'core'"/>
  </xsl:call-template>

  <xsl:call-template name="toc-entry.mpm">
    <xsl:with-param name="current" select="document(concat($basedir, 'mod/', modulefile[starts-with(.,'mpm_common.xml')]/text()))/modulesynopsis"/>
    <xsl:with-param name="name" select="'common'"/>
  </xsl:call-template>

  <xsl:for-each select="modulefile">
  <xsl:sort select="substring-before(substring-after($translist, concat('- ', document(concat($basedir,'mod/',.))/modulesynopsis/name, ' ')), ' -')"/>

    <xsl:variable name="current" select="document(concat($basedir, 'mod/', .))/modulesynopsis" />

    <xsl:if test="$current/status='MPM' and $current/name!='mpm_common'">
      <xsl:call-template name="toc-entry.mpm">
        <xsl:with-param name="current" select="$current"/>
        <xsl:with-param name="name" select="substring-before(substring-after($translist, concat('- ', $current/name, ' ')), ' -')"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:for-each> <!-- /mpm -->

  <xsl:for-each select="modulefile">
  <xsl:sort select="substring-before(substring-after($translist, concat('- ', document(concat($basedir,'mod/',.))/modulesynopsis/name, ' ')), ' -')"/>

    <xsl:variable name="current" select="document(concat($basedir, 'mod/', .))/modulesynopsis" />

    <xsl:if test="$current/status!='MPM' and $current/status!='Core'">
      <xsl:call-template name="toc-entry.module">
        <xsl:with-param name="current" select="$current"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:for-each> <!-- /modules -->

</xsl:template>

<xsl:template name="toc-entry.mpm">
<xsl:param name="current"/>
<xsl:param name="name"/>

  <xsl:text>&lt;li&gt;&lt;object type="text/sitemap"&gt;</xsl:text>&lf;&tab;&tab;&tab;
    <xsl:text>&lt;param name="Name" value="</xsl:text>
      <xsl:call-template name="filter.attval">
        <xsl:with-param name="text"><xsl:choose>
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
        </xsl:with-param>
      </xsl:call-template>
    <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;

    <xsl:text>&lt;param name="Local" value="</xsl:text>
        <xsl:value-of select="concat('mod/', $current/name, '.html')" />
    <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;

    <xsl:text>&lt;param name="ImageNumber" value="</xsl:text>
      <xsl:choose>
        <xsl:when test="$messages/@lang='en' or (document($current/@metafile)/metafile/variants/variant[.=$messages/@lang and not(@htmlonly='yes')])">
          <xsl:value-of select="$icon.document" />
        </xsl:when>

        <xsl:otherwise>
          <xsl:value-of select="$icon.document.not-translated" />
        </xsl:otherwise>
      </xsl:choose>
    <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;
    <xsl:text>&lt;/object&gt;</xsl:text>
    
    <xsl:call-template name="sections-and-directives">
      <xsl:with-param name="current" select="$current" />
    </xsl:call-template>
  <xsl:text>&lt;/li&gt;</xsl:text>&lf;&tab;
</xsl:template>
  
<xsl:template name="toc-entry.module">
<xsl:param name="current"/>

  <xsl:text>&lt;li&gt;&lt;object type="text/sitemap"&gt;</xsl:text>&lf;&tab;&tab;&tab;
    <xsl:text>&lt;param name="Name" value="</xsl:text>
      <xsl:call-template name="filter.attval">
        <xsl:with-param name="text">
          <xsl:value-of select="$messages/message[@name='apachemodule']"/>
          <xsl:text> </xsl:text>
          <xsl:value-of select="$current/name"/>
        </xsl:with-param>
      </xsl:call-template>
    <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;

    <xsl:text>&lt;param name="Local" value="</xsl:text>
        <xsl:value-of select="concat('mod/', $current/name, '.html')" />
    <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;

    <xsl:text>&lt;param name="ImageNumber" value="</xsl:text>
      <xsl:choose>
        <xsl:when test="$messages/@lang='en' or (document($current/@metafile)/metafile/variants/variant[.=$messages/@lang and not(@htmlonly='yes')])">
          <xsl:value-of select="$icon.document" />
        </xsl:when>

        <xsl:otherwise>
          <xsl:value-of select="$icon.document.not-translated" />
        </xsl:otherwise>
      </xsl:choose>
    <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;
    <xsl:text>&lt;/object&gt;</xsl:text>
    
    <xsl:call-template name="sections-and-directives">
      <xsl:with-param name="current" select="$current" />
    </xsl:call-template>
  <xsl:text>&lt;/li&gt;</xsl:text>&lf;&tab;
</xsl:template>

<xsl:template name="sections-and-directives">
<xsl:param name="current" />

  <xsl:if test="count($current/section) > 0 or count($current/directivesynopsis) > 0">
    &lf;&tab;&tab;

    <xsl:text>&lt;ul&gt;</xsl:text>&lf;&tab;&tab;

    <xsl:for-each select="$current/section">
      <xsl:text>&lt;li&gt;&lt;object type="text/sitemap"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;
        <xsl:text>&lt;param name="Name" value="</xsl:text>
          <xsl:call-template name="filter.attval">
            <xsl:with-param name="text" select="normalize-space(title)" />
          </xsl:call-template>
        <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;

        <xsl:if test="@id">
          <xsl:text>&lt;param name="Local" value="</xsl:text>
              <xsl:value-of select="concat('mod/', $current/name, '.html')" />
              <xsl:text>#</xsl:text>
              <xsl:value-of select="@id" />
          <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;
        </xsl:if>

        <xsl:text>&lt;param name="ImageNumber" value="</xsl:text>
            <xsl:if test="@id"><xsl:value-of select="$icon.section"/></xsl:if>
            <xsl:if test="not(@id)">9</xsl:if> <!-- "?" -->
        <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;
      <xsl:text>&lt;/object&gt;&lt;/li&gt;</xsl:text>&lf;&tab;&tab;
    </xsl:for-each> <!-- sections -->

    <xsl:for-each select="$current/directivesynopsis[not(@location)]">
    <xsl:sort select="name"/>

      <xsl:variable name="lowername" select="translate(name, $uppercase, $lowercase)"/>

      <xsl:text>&lt;li&gt;&lt;object type="text/sitemap"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;
        <xsl:text>&lt;param name="Name" value="</xsl:text>
          <xsl:call-template name="filter.attval">
            <xsl:with-param name="text">
              <xsl:if test="@type='section'">&lt;</xsl:if>
              <xsl:value-of select="name"/>
              <xsl:if test="@type='section'">&gt;</xsl:if>
              <xsl:text> </xsl:text>
              <xsl:value-of select="$messages/message[@name='directive']"/>
            </xsl:with-param>
          </xsl:call-template>
        <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;

        <xsl:text>&lt;param name="Local" value="</xsl:text>
            <xsl:value-of select="concat('mod/',$current/name,'.html')" />
            <xsl:text>#</xsl:text>
            <xsl:value-of select="$lowername" />
        <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;

        <xsl:text>&lt;param name="ImageNumber" value="</xsl:text>
            <xsl:value-of select="$icon.directive" />
        <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;
      <xsl:text>&lt;/object&gt;&lt;/li&gt;</xsl:text>&lf;&tab;&tab;
    </xsl:for-each> <!-- directivesynopsis -->

    <xsl:for-each select="$current/directivesynopsis[@location]">
    <xsl:sort select="name"/>

      <xsl:variable name="lowername" select="translate(name, $uppercase, $lowercase)"/>

      <xsl:text>&lt;li&gt;&lt;object type="text/sitemap"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;
        <xsl:text>&lt;param name="Name" value="</xsl:text>
          <xsl:call-template name="filter.attval">
            <xsl:with-param name="text">
              <xsl:if test="@type='section'">&lt;</xsl:if>
              <xsl:value-of select="name"/>
              <xsl:if test="@type='section'">&gt;</xsl:if>
              <xsl:text> </xsl:text>
              <xsl:value-of select="$messages/message[@name='directive']"/>
            </xsl:with-param>
          </xsl:call-template>
        <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;

        <xsl:text>&lt;param name="Local" value="</xsl:text>
            <xsl:value-of select="concat('mod/',@location,'.html')" />
            <xsl:text>#</xsl:text>
            <xsl:value-of select="$lowername" />
        <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;&tab;

        <xsl:text>&lt;param name="ImageNumber" value="</xsl:text>
            <xsl:value-of select="$icon.commondirective" />
        <xsl:text>"&gt;</xsl:text>&lf;&tab;&tab;&tab;
      <xsl:text>&lt;/object&gt;&lt;/li&gt;</xsl:text>&lf;&tab;&tab;
    </xsl:for-each> <!-- directivesynopsis -->

    <xsl:text>&lt;/ul&gt;</xsl:text>&lf;&tab;
  </xsl:if> <!-- sections or directives present -->

</xsl:template>

<xsl:template name="filter.attval">
<xsl:param name="text"/>

    <xsl:choose>
        <xsl:when test="contains($text, '&amp;')">
            <xsl:call-template name="filter.attval.special">
              <xsl:with-param name="text" select="substring-before($text, '&amp;')"/>
            </xsl:call-template>
            <xsl:text>&amp;amp;</xsl:text>
            <xsl:call-template name="filter.attval">
                <xsl:with-param name="text"
                              select="substring-after($text, '&amp;')"/>
            </xsl:call-template>
        </xsl:when>

        <xsl:otherwise>
          <xsl:call-template name="filter.attval.special">
            <xsl:with-param name="text" select="$text"/>
          </xsl:call-template>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<xsl:template name="filter.attval.special">
<xsl:param name="text"/>

    <xsl:choose>
        <xsl:when test="contains($text, '&lt;')">
            <xsl:value-of select="substring-before($text, '&lt;')"/>
            <xsl:text>&amp;lt;</xsl:text>
            <xsl:call-template name="filter.attval.special">
                <xsl:with-param name="text"
                              select="substring-after($text, '&lt;')"/>
            </xsl:call-template>
        </xsl:when>

        <xsl:when test="contains($text, '&gt;')">
            <xsl:value-of select="substring-before($text, '&gt;')"/>
            <xsl:text>&amp;gt;</xsl:text>
            <xsl:call-template name="filter.attval.special">
                <xsl:with-param name="text"
                              select="substring-after($text, '&gt;')"/>
            </xsl:call-template>
        </xsl:when>

        <xsl:when test="contains($text, '&quot;')">
            <xsl:value-of select="substring-before($text, '&quot;')"/>
            <xsl:text>&amp;quot;</xsl:text>
            <xsl:call-template name="filter.attval.special">
                <xsl:with-param name="text"
                              select="substring-after($text, '&quot;')"/>
            </xsl:call-template>
        </xsl:when>

        <xsl:otherwise>
            <xsl:value-of select="$text"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

</xsl:stylesheet>

