<?xml version="1.0"?><!--
/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */ -->
<!DOCTYPE xsl:stylesheet [
    <!ENTITY lf SYSTEM "../xsl/util/lf.xml">
    <!ENTITY tab SYSTEM "../xsl/util/tab.xml">

    <!ENTITY ul.start SYSTEM "../xsl/util/ul-start.xml">
    <!ENTITY ul.end SYSTEM   "../xsl/util/ul-end.xml"  >
    <!ENTITY li.start SYSTEM "../xsl/util/li-start.xml">
    <!ENTITY li.end SYSTEM   "../xsl/util/li-end.xml"  >
]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="">

<!--                                                                      -->
<!-- WARNING! Do not touch anything, especially the whitespaces [1]       -->
<!-- unless you know, what you're doing. The HTML help compiler parses    -->
<!-- the TOC file not really as html instead of line by line and takes    -->
<!-- care of whitespace indentations etc.                                 -->
<!--                                                                      -->
<!--   [1] Covered by the &lf; and &tab; entities.                        -->
<!--                                                                      -->
<!-- You have been warned.                                                -->
<!--                                                                      -->

<!-- create nodeset for referencing later                                 -->
<xsl:variable name="not-exists" select="document('')/xsl:stylesheet/xsl:template
                                        [@name='data']/not-exists/file" />

<xsl:template name="data">
<!-- documents not converted (yet?). -->
<not-exists>
    <file>developer/API.xml</file>
</not-exists>
</xsl:template>

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
<!-- this should not happen. this icon is only displayed within the
     toc view of the help workshop (it's a question mark): -->
<xsl:variable name="icon.no-anchor" select="'9'" />

<!-- for module-translatename -->
<xsl:include href="../xsl/util/modtrans.xsl"/>

<!-- ==================================================================== -->
<!-- <sitemap>                                                            -->
<!-- Create CHM contents file (toc) from sitemap                          -->
<!-- The file is an html style text file (see warning on top)             -->
<!-- ==================================================================== -->
<xsl:template match="/sitemap">

<!-- html head -->
<xsl:text>&lt;html&gt;&lt;head&gt;</xsl:text>
<xsl:text>&lt;title&gt;Apache HTTP Server Documentation&lt;/title&gt;</xsl:text>
<xsl:text>&lt;/head&gt;</xsl:text>&lf;

<xsl:text>&lt;body&gt;</xsl:text>&lf;

<!-- toc properties first -->
<xsl:text>&lt;object type="text/site properties"&gt;</xsl:text>&lf;&tab;
<!-- XXX: that magic value is still obfuscated. Research needed ... -->
<xsl:text>&lt;param name="Window Styles" value="0x800027"&gt;</xsl:text>&lf;&tab;
<xsl:text>&lt;param name="Font" value="</xsl:text>
    <xsl:value-of select="$toc-font" />
<xsl:text>"&gt;</xsl:text>&lf;
<xsl:text>&lt;/object&gt;</xsl:text>&lf;

&ul.start; &lf;

    <!-- index page on top. -->
    &li.start;
    <xsl:call-template name="object">
        <xsl:with-param name="name"
            select="$messages/message[@name='apachehttpserver']" />
        <xsl:with-param name="href" select="'index.html'" />
        <xsl:with-param name="indent" select="'&#9;&#9;'" />
    </xsl:call-template>
    &li.end; &lf;

    <!-- iterate over the categories in document order -->
    <xsl:for-each select="category">
        &li.start;
        <xsl:call-template name="folder">
            <xsl:with-param name="name" select="normalize-space(title)" />
        </xsl:call-template>&lf;&tab;

        &ul.start; &lf;&tab;
            <xsl:apply-templates select="page" />
            <xsl:apply-templates select="modulefilelist" />
        &ul.end; &lf;
        &li.end; &lf;&tab;
    </xsl:for-each>&lf;

&ul.end; &lf;

<xsl:text>&lt;/body&gt;&lt;/html&gt;</xsl:text>&lf;
</xsl:template>
<!-- /sitemap -->


<!-- ==================================================================== -->
<!-- category/page                                                        -->
<!-- ==================================================================== -->
<xsl:template match="category/page">
&li.start;

<!-- document entry, if not href attribute, assume it means "sitemap" -->
<xsl:call-template name="object">
    <xsl:with-param name="name">
        <xsl:choose>
        <xsl:when test="@href">
            <xsl:value-of select="normalize-space(.)" />
        </xsl:when>
        <xsl:otherwise>
            <xsl:value-of select="normalize-space($messages/message
                                                  [@name='sitemap'])" />
        </xsl:otherwise>
        </xsl:choose>
    </xsl:with-param>
    <xsl:with-param name="href">
        <xsl:choose>
        <xsl:when test="not(@href)">
            <xsl:text>sitemap.html</xsl:text>
        </xsl:when>
        <xsl:when test="contains(@href, '#')">
            <xsl:value-of select="substring-before(@href, '#')" />
        </xsl:when>
        <xsl:otherwise>
            <xsl:value-of select="@href"/>
        </xsl:otherwise>
        </xsl:choose>
    </xsl:with-param>
    <xsl:with-param name="indent" select="'&#9;&#9;'" />
</xsl:call-template>

<!-- now try to index the sections of the document -->
<xsl:apply-templates select="self::page" mode="index" />

&li.end; &lf;&tab;
</xsl:template>
<!-- /category/page -->


<!-- ==================================================================== -->
<!-- category/page, mode="index"                                          -->
<!-- display all section headings of one page                             -->
<!-- ==================================================================== -->
<xsl:template match="category/page" mode="index">
<xsl:variable name="href.offline">
    <xsl:choose>
    <xsl:when test="string-length(@href) = 0">
        <xsl:text>sitemap.html</xsl:text>
    </xsl:when>
    <xsl:otherwise>
        <xsl:call-template name="helper.href.offline">
            <xsl:with-param name="href" select="@href" />
        </xsl:call-template>
    </xsl:otherwise>
    </xsl:choose>
</xsl:variable>
<xsl:variable name="xml"
    select="concat(substring-before($href.offline, '.html'), '.xml')" />

<xsl:if test="not($xml = $not-exists)">
    <xsl:variable name="xmlfile">
        <xsl:variable name="metafile"
            select="document(document(concat($basedir, $xml))/*/@metafile)
                    /metafile" />
        <xsl:choose>
        <xsl:when test="$metafile/variants/variant[.=$messages/@lang] and not
                        ($metafile/variants/variant[.=$messages/@lang]
                         /@htmlonly = 'yes')">
                <xsl:value-of select="concat($basedir,
                                   substring-before($xml, '.xml'), $xml-ext)" />
        </xsl:when>
        <xsl:otherwise>
            <xsl:value-of select="concat($basedir, $xml)" />
        </xsl:otherwise>
        </xsl:choose>
    </xsl:variable>

    <xsl:variable name="current" select="document($xmlfile)" />

    <xsl:if test="count($current/*/*[local-name()='section' or
                                     local-name()='category']) &gt; 1">
        &lf;&tab;&tab;&tab;
        &ul.start; &lf;&tab;&tab;&tab;

        <xsl:for-each select="$current/*/*[local-name()='section' or
                                           local-name()='category']">
            &li.start;

            <xsl:call-template name="object">
                <xsl:with-param name="name" select="normalize-space(title)" />
                <xsl:with-param name="href">
                    <xsl:if test="@id">
                        <xsl:value-of
                            select="concat(substring-before($xml, '.xml'),
                                           '.html#', @id)" />
                    </xsl:if>
                </xsl:with-param>
                <xsl:with-param name="indent" select="'&#9;&#9;&#9;&#9;'" />
            </xsl:call-template>

            &li.end; &lf;&tab;&tab;
        </xsl:for-each>

        &ul.end; &lf;&tab;
    </xsl:if> <!-- count() > 1 -->
</xsl:if> <!-- xml exists -->
</xsl:template>
<!-- /category/page, "index" -->


<!-- ==================================================================== -->
<!-- category/modulefilelist                                              -->
<!-- process all listed module files                                      -->
<!-- ==================================================================== -->
<xsl:template match="category/modulefilelist">
<!-- create a module name translation list for sorting -->
<xsl:variable name="translist">
    <xsl:text>-</xsl:text>

    <xsl:for-each select="modulefile">
        <xsl:variable name="current"
            select="document(concat($basedir,'mod/',.))/modulesynopsis" />
   
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
    <xsl:with-param name="current"
        select="document(concat($basedir, 'mod/', modulefile[starts-with(.,
                         'core.xml')]/text()))/modulesynopsis" />
    <xsl:with-param name="name" select="'core'" />
</xsl:call-template>

<xsl:call-template name="toc-entry.mpm">
    <xsl:with-param name="current"
        select="document(concat($basedir, 'mod/', modulefile[starts-with(.,
                         'mpm_common.xml')]/text()))/modulesynopsis" />
    <xsl:with-param name="name" select="'common'" />
</xsl:call-template>

<!-- remaining MPMs -->
<xsl:for-each select="modulefile">
<xsl:sort select="substring-before(substring-after($translist, concat('- ',
    document(concat($basedir, 'mod/', .))/modulesynopsis/name, ' ')), ' -')" />

    <xsl:variable name="current"
        select="document(concat($basedir, 'mod/', .))/modulesynopsis" />

    <xsl:if test="$current/status='MPM' and not($current/name='mpm_common')">
        <xsl:call-template name="toc-entry.mpm">
            <xsl:with-param name="current" select="$current" />
            <xsl:with-param name="name" select="substring-before(
                substring-after($translist, concat('- ', $current/name, ' ')),
                ' -')" />
        </xsl:call-template>
    </xsl:if>
</xsl:for-each>

<!-- normal modules -->
<xsl:for-each select="modulefile">
<xsl:sort select="substring-before(substring-after($translist, concat('- ',
    document(concat($basedir, 'mod/', .))/modulesynopsis/name, ' ')), ' -')" />

    <xsl:variable name="current"
        select="document(concat($basedir, 'mod/', .))/modulesynopsis" />

    <xsl:if test="not($current/status='MPM') and not($current/status='Core')">
        <xsl:call-template name="toc-entry.module">
            <xsl:with-param name="current" select="$current"/>
        </xsl:call-template>
    </xsl:if>
</xsl:for-each>
</xsl:template>
<!-- /category/modulefilelist -->


<!-- ==================================================================== -->
<!-- toc-entry.mpm                                                        -->
<!-- create entry (and initiate subsection entries) of an mpm             -->
<!-- ==================================================================== -->
<xsl:template name="toc-entry.mpm">
<xsl:param name="current" />
<xsl:param name="name" />

&li.start;

<xsl:call-template name="object">
    <xsl:with-param name="name">
        <xsl:choose>
        <xsl:when test="$name='core'">
            <xsl:value-of select="$messages/message[@name='apachecore']" />
        </xsl:when>
        <xsl:when test="$name='common'">
            <xsl:value-of select="$messages/message[@name='apachempmcommon']" />
        </xsl:when>
        <xsl:otherwise>
            <xsl:value-of select="$messages/message[@name='apachempm']" />
            <xsl:text> </xsl:text>
            <xsl:value-of select="$name" />
        </xsl:otherwise>
        </xsl:choose>
    </xsl:with-param>
    <xsl:with-param name="href"
        select="concat('mod/', $current/name, '.html')" />
    <xsl:with-param name="indent" select="'&#9;&#9;&#9;'" />
</xsl:call-template>
    
<xsl:call-template name="sections-and-directives">
    <xsl:with-param name="current" select="$current" />
</xsl:call-template>

&li.end; &lf;&tab;
</xsl:template>
<!-- /toc-entry.mpm -->
  

<!-- ==================================================================== -->
<!-- toc-entry.module                                                     -->
<!-- create entry (and initiate subsection entries) of a module           -->
<!-- ==================================================================== -->
<xsl:template name="toc-entry.module">
<xsl:param name="current"/>

&li.start;

<xsl:call-template name="object">
    <xsl:with-param name="name">
        <xsl:value-of select="$messages/message[@name='apachemodule']" />
        <xsl:text> </xsl:text>
        <xsl:value-of select="$current/name" />
    </xsl:with-param>
    <xsl:with-param name="href"
        select="concat('mod/', $current/name, '.html')" />
    <xsl:with-param name="indent" select="'&#9;&#9;&#9;'" />
</xsl:call-template>
    
<xsl:call-template name="sections-and-directives">
    <xsl:with-param name="current" select="$current" />
</xsl:call-template>

&li.end; &lf;&tab;
</xsl:template>
<!-- /toc-entry.module -->


<!-- ==================================================================== -->
<!-- sections-and-directives                                              -->
<!-- process sections and directives of a module file                     -->
<!-- ==================================================================== -->
<xsl:template name="sections-and-directives">
<xsl:param name="current" />

<xsl:if test="count($current/section) &gt; 0 or
              count($current/directivesynopsis) &gt; 0">
    &lf;&tab;&tab;

    &ul.start; &lf;&tab;&tab;

    <!-- sections -->
    <xsl:for-each select="$current/section">
        &li.start;

        <xsl:call-template name="object">
            <xsl:with-param name="name" select="normalize-space(title)" />
            <xsl:with-param name="href">
                <xsl:if test="@id">
                    <xsl:value-of
                        select="concat('mod/', $current/name, '.html#', @id)" />
                </xsl:if>
            </xsl:with-param>
            <xsl:with-param name="indent" select="'&#9;&#9;&#9;&#9;'" />
        </xsl:call-template>

        &li.end; &lf;&tab;&tab;
    </xsl:for-each>

    <!-- directives within the current document -->
    <xsl:for-each select="$current/directivesynopsis[not(@location)]">
    <xsl:sort select="name" />
        &li.start;

        <xsl:call-template name="object">
            <xsl:with-param name="name">
                <xsl:if test="@type='section'">&lt;</xsl:if>
                <xsl:value-of select="name"/>
                <xsl:if test="@type='section'">&gt;</xsl:if>
                <xsl:choose>
                <xsl:when test="$messages/message[@name='directive']
                                /@replace-space-with">
                    <xsl:value-of select="$messages/message[@name='directive']
                                          /@replace-space-with" />
                </xsl:when>
                <xsl:otherwise>
                    <xsl:text> </xsl:text>
                </xsl:otherwise>
                </xsl:choose>
                <xsl:value-of select="$messages/message[@name='directive']" />
            </xsl:with-param>
            <xsl:with-param name="href"
                select="concat('mod/', $current/name, '.html#',
                               translate(name, $uppercase, $lowercase))" />
            <xsl:with-param name="indent" select="'&#9;&#9;&#9;&#9;'" />
            <xsl:with-param name="icon" select="$icon.directive" />
        </xsl:call-template>

        &li.end; &lf;&tab;&tab;
    </xsl:for-each>

    <!-- directives described elsewhere -->
    <xsl:for-each select="$current/directivesynopsis[@location]">
    <xsl:sort select="name" />
        &li.start;

        <xsl:call-template name="object">
            <xsl:with-param name="name">
                <xsl:if test="@type='section'">&lt;</xsl:if>
                <xsl:value-of select="name"/>
                <xsl:if test="@type='section'">&gt;</xsl:if>
                <xsl:choose>
                <xsl:when test="$messages/message[@name='directive']
                                /@replace-space-with">
                    <xsl:value-of select="$messages/message[@name='directive']
                                          /@replace-space-with" />
                </xsl:when>
                <xsl:otherwise>
                    <xsl:text> </xsl:text>
                </xsl:otherwise>
                </xsl:choose>
                <xsl:value-of select="$messages/message[@name='directive']" />
            </xsl:with-param>
            <xsl:with-param name="href"
                select="concat('mod/', @location, '.html#',
                               translate(name, $uppercase, $lowercase))" />
            <xsl:with-param name="indent" select="'&#9;&#9;&#9;&#9;'" />
            <xsl:with-param name="icon" select="$icon.commondirective" />
        </xsl:call-template>

        &li.end; &lf;&tab;&tab;
    </xsl:for-each>

    &ul.end; &lf;&tab;
</xsl:if> <!-- sections or directives present -->
</xsl:template>
<!-- /sections-and-directives -->


<!-- ==================================================================== -->
<!-- object                                                               -->
<!-- display an <object> and do some magic to select the right content    -->
<!-- ==================================================================== -->
<xsl:template name="object">
<xsl:param name="name" select="'? unknown ?'" />
<xsl:param name="href" />
<xsl:param name="icon" select="$icon.section" />
<xsl:param name="indent" />

<xsl:variable name="href.offline">
    <xsl:call-template name="helper.href.offline">
        <xsl:with-param name="href" select="$href" />
    </xsl:call-template>
</xsl:variable>

<!-- xml file is expected to have the same basename -->
<xsl:variable name="xml"
    select="concat(substring-before($href.offline, '.html'), '.xml')" />

<xsl:text>&lt;object type="text/sitemap"&gt;</xsl:text>&lf;
<xsl:value-of select="$indent" />

<xsl:text>&lt;param name="Name" value="</xsl:text>
    <xsl:call-template name="filter.attval">
        <xsl:with-param name="text" select="$name" />
    </xsl:call-template>
<xsl:text>"&gt;</xsl:text>&lf;
<xsl:value-of select="$indent" />

<xsl:if test="string-length($href.offline) &gt; 0">
    <xsl:text>&lt;param name="Local" value="</xsl:text>
        <xsl:call-template name="filter.attval">
            <xsl:with-param name="text" select="$href.offline" />
        </xsl:call-template>
    <xsl:text>"&gt;</xsl:text>&lf;
    <xsl:value-of select="$indent" />
</xsl:if>

<xsl:text>&lt;param name="ImageNumber" value="</xsl:text>
    <xsl:choose>
    <xsl:when test="string-length($href.offline) &gt; 0">
        <xsl:choose>
        <xsl:when test="contains($href, '#')">
            <xsl:value-of select="$icon" />
        </xsl:when>
        <xsl:when test="$messages/@lang='en' or
                        (not($xml = $not-exists) and
                         (document(document(concat($basedir, $xml))
                                   /*/@metafile)
                          /metafile/variants/variant
                          [.=$messages/@lang and not(@htmlonly='yes')]))">
            <xsl:value-of select="$icon.document" />
        </xsl:when>
        <xsl:otherwise>
            <xsl:value-of select="$icon.document.not-translated" />
        </xsl:otherwise>
        </xsl:choose>
    </xsl:when>
    <xsl:otherwise>
        <xsl:value-of select="$icon.no-anchor" />
    </xsl:otherwise>
    </xsl:choose>
<xsl:text>"&gt;</xsl:text>&lf;
<xsl:value-of select="substring($indent, 2)" />

<xsl:text>&lt;/object&gt;</xsl:text>
</xsl:template>
<!-- /object -->


<!-- ==================================================================== -->
<!-- folder                                                               -->
<!-- ==================================================================== -->
<xsl:template name="folder">
<xsl:param name="name" select="'? unknown ?'" />

<xsl:text>&lt;object type="text/sitemap"&gt;</xsl:text>&lf;&tab;&tab;
<xsl:text>&lt;param name="Name" value="</xsl:text>
    <xsl:call-template name="filter.attval">
        <xsl:with-param name="text" select="$name" />
    </xsl:call-template>
<xsl:text>"&gt;</xsl:text>&lf;&tab;
<xsl:text>&lt;/object&gt;</xsl:text>
</xsl:template>
<!-- /folder -->


<!-- ==================================================================== -->
<!-- helper.href.offline                                                  -->
<!-- change uri reference to work offline (/ -> /index.html)              -->
<!-- ==================================================================== -->
<xsl:template name="helper.href.offline">
<xsl:param name="href" />

<xsl:choose>
<xsl:when test="string-length($href) = 0" />
<xsl:when test="contains($href, '#') and '/' = substring($href,
                               string-length(substring-before($href, '#')), 1)">
    <xsl:value-of select="substring-before($href, '#')" />
    <xsl:text>index.html#</xsl:text>
    <xsl:value-of select="substring-after($href, '#')" />
</xsl:when>
<xsl:when test="substring($href, string-length($href), 1) = '/'">
    <xsl:value-of select="$href" />
    <xsl:text>index.html</xsl:text>
</xsl:when>
<xsl:otherwise>
    <xsl:value-of select="$href" />
</xsl:otherwise>
</xsl:choose>
</xsl:template>
<!-- /helper.href.offline -->


<!-- ==================================================================== -->
<!-- filter.attval                                                        -->
<!-- escape special characters for being valid within an attribute        -->
<!-- ==================================================================== -->
<xsl:template name="filter.attval">
<xsl:param name="text" />

<xsl:choose>
<xsl:when test="contains($text, '&amp;')">
    <xsl:call-template name="filter.attval.special">
        <xsl:with-param name="text" select="substring-before($text, '&amp;')" />
    </xsl:call-template>
    <xsl:text>&amp;amp;</xsl:text>
    <xsl:call-template name="filter.attval">
        <xsl:with-param name="text" select="substring-after($text, '&amp;')" />
    </xsl:call-template>
</xsl:when>
<xsl:otherwise>
    <xsl:call-template name="filter.attval.special">
        <xsl:with-param name="text" select="$text" />
    </xsl:call-template>
</xsl:otherwise>
</xsl:choose>
</xsl:template>
<!-- /filter.attval -->


<!-- ==================================================================== -->
<!-- filter.attval.special                                                -->
<!-- accompanying template of filter.attval                               -->
<!-- ==================================================================== -->
<xsl:template name="filter.attval.special">
<xsl:param name="text" />

<xsl:choose>
<xsl:when test="contains($text, '&lt;')">
    <xsl:value-of select="substring-before($text, '&lt;')" />
    <xsl:text>&amp;lt;</xsl:text>
    <xsl:call-template name="filter.attval.special">
        <xsl:with-param name="text" select="substring-after($text, '&lt;')" />
    </xsl:call-template>
</xsl:when>
<xsl:when test="contains($text, '&gt;')">
    <xsl:value-of select="substring-before($text, '&gt;')" />
    <xsl:text>&amp;gt;</xsl:text>
    <xsl:call-template name="filter.attval.special">
        <xsl:with-param name="text" select="substring-after($text, '&gt;')" />
    </xsl:call-template>
</xsl:when>
<xsl:when test="contains($text, '&quot;')">
    <xsl:value-of select="substring-before($text, '&quot;')" />
    <xsl:text>&amp;quot;</xsl:text>
    <xsl:call-template name="filter.attval.special">
        <xsl:with-param name="text" select="substring-after($text, '&quot;')" />
    </xsl:call-template>
</xsl:when>
<xsl:otherwise>
    <xsl:value-of select="$text" />
</xsl:otherwise>
</xsl:choose>
</xsl:template>
<!-- /filter.attval.special -->

</xsl:stylesheet>
