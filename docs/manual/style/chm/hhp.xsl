<?xml version="1.0"?><!--
/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2003-2004 The Apache Software Foundation.  All rights
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
]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="">

<!-- create nodeset for referencing later                                 -->
<xsl:variable name="htmlhelp.def" select="document('')/xsl:stylesheet
                                        /xsl:template[@name='htmlhelp.def']" />

<!-- ==================================================================== -->
<!-- <sitemap>                                                            -->
<!-- Create CHM project file from sitemap                                 -->
<!-- The file is an *.ini format text file                                -->
<!-- ==================================================================== -->
<xsl:template match="/sitemap">

<!-- static information                                               -->
<!-- **************************************************************** -->
<xsl:text>[OPTIONS]</xsl:text>&lf;
<xsl:text>Binary TOC=No</xsl:text>&lf;
<xsl:text>Compatibility=1.0</xsl:text>&lf;

<!-- resulting filename -->
<xsl:text>Compiled file=manual.</xsl:text>
<xsl:value-of select="$messages/@lang" />
<xsl:text>.chm</xsl:text>&lf;

<xsl:text>Contents file=toc.hhc</xsl:text>&lf;
<xsl:text>Default Window=Main</xsl:text>&lf;
<xsl:text>Default topic=index.html</xsl:text>&lf;

<!-- compiler related -->
<xsl:text>Display compile progress=Yes</xsl:text>&lf;
<xsl:text>Enhanced decompilation=Yes</xsl:text>&lf;

<!-- search related -->
<xsl:text>Full-text search=Yes</xsl:text>&lf;
<xsl:text>Language=</xsl:text>
<xsl:value-of select="$hhp-lang" />&lf;

<!-- title of the help file -->
<xsl:text>Title=</xsl:text>
<xsl:value-of select="$messages/message[@name='apachehttpserver']"/>&lf;&lf;

<!-- main window definition -->
<xsl:text>[WINDOWS]</xsl:text>&lf;
<xsl:text>Main=</xsl:text>

<!-- title -->
<xsl:text>"</xsl:text>
<xsl:value-of select="$messages/message[@name='apachehttpserver']"/>
<xsl:text>",</xsl:text>

<!-- toc file -->
<xsl:text>"toc.hhc",</xsl:text>

<!-- index file (currently none) -->
<xsl:text>,</xsl:text>

<!-- default file (startup) -->
<xsl:text>"index.html",</xsl:text>

<!-- Home button file -->
<xsl:text>"index.html",</xsl:text>

<!-- Jump 1 url, text -->
<xsl:text>,,</xsl:text>

<!-- Jump 2 url, text -->
<xsl:text>,,</xsl:text>

<!-- navigation pane style (0x1e357e) -->
<xsl:call-template name="helper.number2hex">
    <xsl:with-param name="number" select="sum($htmlhelp.def/navigation/style
                                              [@selected='yes'])" />
</xsl:call-template>
<xsl:text>,</xsl:text>

<!-- navigation pane initial width (px) -->
<xsl:text>180,</xsl:text>

<!-- button mask -->
<xsl:call-template name="helper.number2hex">
    <xsl:with-param name="number" select="sum($htmlhelp.def/buttons/button
                                              [@visible='yes'])" />
</xsl:call-template>
<xsl:text>,</xsl:text>

<!-- Initial Position [Left, Top, Right, Bottom] -->
<xsl:text>[0,0,600,380],</xsl:text>

<!-- window style -->
<xsl:call-template name="helper.number2hex">
    <xsl:with-param name="result" select="'0000'" /> <!-- << 16 -->
    <xsl:with-param name="number" select="sum($htmlhelp.def/windowstyle/style
                                              [@selected='yes'])" />
</xsl:call-template>
<xsl:text>,</xsl:text>

<!-- extended style -->
<xsl:text>,</xsl:text>

<!-- flag: navigation pane initial closed (=1) -->
<xsl:text>,</xsl:text>

<!-- unknown, default pane, unknown, unknown -->
<xsl:text>,,,0</xsl:text>&lf;&lf;

<!-- file list                                                        -->
<!-- **************************************************************** -->
<xsl:text>[FILES]</xsl:text>&lf;

<!-- not automatically sucked in. (because only @import()ed) -->
<xsl:text>style\css\manual.css</xsl:text>&lf;
<xsl:text>style\css\manual-loose-100pc.css</xsl:text>&lf;

<!-- include project file itself for easier recompiling -->
<xsl:text>manual.hhp</xsl:text>&lf;

<!-- and now all sitemap-listed files -->
<xsl:for-each select="category">
    <xsl:apply-templates select="page[@href]" />
    <xsl:apply-templates select="modulefilelist/modulefile"/>
</xsl:for-each>&lf;
</xsl:template>
<!-- /sitemap -->


<!-- ==================================================================== -->
<!-- files referenced in sitemap                                          -->
<!-- ==================================================================== -->
<xsl:template match="category/page">
<xsl:variable name="filename">
    <xsl:choose>
    <xsl:when test="contains(@href, '#') and substring(@href,
                    string-length(substring-before(@href, '#')), 1) = '/'">
        <xsl:value-of select="substring-before(@href, '#')" />
        <xsl:text>index.html</xsl:text>
    </xsl:when>
    <xsl:when test="substring(@href, string-length(@href), 1) = '/'">
        <xsl:value-of select="@href"/>
        <xsl:text>index.html</xsl:text>
    </xsl:when>
    <xsl:otherwise>
        <xsl:value-of select="@href"/>
    </xsl:otherwise>
    </xsl:choose>
</xsl:variable>

<xsl:value-of select="translate($filename, '/', '\')" />&lf;
</xsl:template>
<!-- /page[@href] -->


<!-- ==================================================================== -->
<!-- list module files                                                    -->
<!-- ==================================================================== -->
<xsl:template match="category/modulefilelist/modulefile">
<xsl:text>mod\</xsl:text>
<xsl:value-of select="substring-before(normalize-space(.), '.xml')" />
<xsl:text>.html</xsl:text>&lf;
</xsl:template>
<!-- /modulefilelist/modulefile -->


<!-- ==================================================================== -->
<!-- convert number to its hexadecimal representation.                    -->
<!-- I could not find a built-in function, so write our own ... *sigh*    -->
<!-- ==================================================================== -->
<xsl:template name="helper.number2hex">
<xsl:param name="number" />
<xsl:param name="result" />

<xsl:choose>
<xsl:when test="number($number) &gt; 0">
    <xsl:call-template name="helper.number2hex">
        <xsl:with-param name="number" select="floor(number($number) div 16)" />
        <xsl:with-param name="result"
            select="concat(substring('0123456789abcdef',
                                     (number($number) mod 16) + 1, 1),
                           $result)" />
    </xsl:call-template>
</xsl:when>
<xsl:otherwise>
    <!-- if zero, don't print anything. hh.exe (the viewer) seems to -->
    <!-- prefer an empty value -->
    <xsl:if test="string-length(translate($result, '0', '')) &gt; 0">
        <xsl:text>0x</xsl:text>
        <xsl:value-of select="$result" />
    </xsl:if>
</xsl:otherwise>
</xsl:choose>
</xsl:template>
<!-- /helper.number2hex -->


<!-- ==================================================================== -->
<!-- some of the values are derived from htmlhelp.h                       -->
<!-- do NOT call this template, it's referenced automagically via         -->
<!-- document() function and acts as simple data container.               -->
<!--                                                                      -->
<!-- Hints: 'ni' means 'not implemented' (by the help viewer)             -->
<!--        'ns' means 'not useful for standalone help file'              -->
<!-- ==================================================================== -->
<xsl:template name="htmlhelp.def">
<navigation>
    <style               >        1</style> <!-- auto hide nav. pane   <<  0 -->
    <style               >        2</style> <!-- ns: topmost window    <<  1 -->
    <style               >        4</style> <!-- ns: no title bar      <<  2 -->
    <style               >        8</style> <!-- ns: no win. style     <<  3 -->
    <style               >       16</style> <!-- ns: no ext. style     <<  4 -->
    <style selected="yes">       32</style> <!-- use tri-pane win.     <<  5 -->
    <style               >       64</style> <!-- no toolbar text       <<  6 -->
    <style               >      128</style> <!-- ns: send WM_QUIT      <<  7 -->
    <style selected="yes">      256</style> <!-- toc auto sync         <<  8 -->
    <style               >      512</style> <!-- ns: send track. not.  <<  9 -->
    <style selected="yes">     1024</style> <!-- search tab            << 10 -->
    <style               >     2048</style> <!-- ni(?): history tab    << 11 -->
    <style selected="yes">     4096</style> <!-- favorites tab         << 12 -->
    <style               >     8192</style> <!-- ni(?): title sync     << 13 -->
    <style               >    16384</style> <!-- nav. only             << 14 -->
    <style               >    32768</style> <!-- no toolbar            << 15 -->
    <style selected="yes">    65536</style> <!-- show menu             << 16 -->
    <style selected="yes">   131072</style> <!-- advanced search       << 17 -->
    <style selected="yes">   262144</style> <!-- safe user's win. size << 18 -->
    <style               >   524288</style> <!-- custom tab 1          << 19 -->
    <style               >  1048576</style> <!-- custom tab 2          << 20 -->
    <style               >  2097152</style> <!-- custom tab 3          << 21 -->
    <style               >  4194304</style> <!-- custom tab 4          << 22 -->
    <style               >  8388608</style> <!-- custom tab 5          << 23 -->
    <style               > 16777216</style> <!-- custom tab 6          << 24 -->
    <style               > 33554432</style> <!-- custom tab 7          << 25 -->
    <style               > 67108864</style> <!-- custom tab 8          << 26 -->
    <style               >134217728</style> <!-- custom tab 9          << 27 -->
    <style               >268435456</style> <!-- window has margin (?) << 28 -->
</navigation>

<buttons>
    <button visible="yes">      2</button> <!-- expand/contract   <<  1 -->
    <button visible="yes">      4</button> <!-- back              <<  2 -->
    <button visible="yes">      8</button> <!-- forward           <<  3 -->
    <button visible="yes">     16</button> <!-- Stop              <<  4 -->
    <button              >     32</button> <!-- Refresh           <<  5 -->
    <button visible="yes">     64</button> <!-- Home              <<  6 -->
    <button              >    128</button> <!-- ni: browse fwd    <<  7 -->
    <button              >    256</button> <!-- ni: browse back   <<  8 -->
    <button              >    512</button> <!-- ni: notes         <<  9 -->
    <button              >   1024</button> <!-- ni: contents      << 10 -->
    <button visible="yes">   2048</button> <!-- Sync TOC          << 11 -->
    <button visible="yes">   4096</button> <!-- Options           << 12 -->
    <button visible="yes">   8192</button> <!-- Print             << 13 -->
    <button              >  16384</button> <!-- ni: index         << 14 -->
    <button              >  32768</button> <!-- ni: search        << 15 -->
    <button              >  65536</button> <!-- ni: history       << 16 -->
    <button              > 131072</button> <!-- ni: favorites     << 17 -->
    <button              > 262144</button> <!-- Jump 1            << 18 -->
    <button              > 524288</button> <!-- Jump 2            << 19 -->
    <button visible="yes">1048576</button> <!-- (Font) Zoom       << 20 -->
    <!-- the following work only with binary toc, which unfortunately   -->
    <!-- seems to eat the different icons ...                           -->
    <button              >2097152</button> <!-- TOC next          << 21 -->
    <button              >4194304</button> <!-- TOC prev          << 22 -->
</buttons>

<windowstyle>
    <!-- all the stuff is additionally shifted << 16 (by the caller) -->
    <style selected="yes">    1</style> <!-- maximize box     <<  0 -->
    <style selected="yes">    2</style> <!-- minimize box     <<  1 -->
    <style selected="yes">    4</style> <!-- thick frame      <<  2 -->
    <style selected="yes">    8</style> <!-- system menu      <<  3 -->
    <style               >   16</style> <!-- horiz. scroll    <<  4 -->
    <style               >   32</style> <!-- vertic. scroll   <<  5 -->
    <style selected="yes">   64</style> <!-- dialog frame     <<  6 -->
    <style selected="yes">  128</style> <!-- border           <<  7 -->
    <style selected="yes">  256</style> <!-- maximize         <<  8 -->
    <style               >  512</style> <!-- clip child win.  <<  9 -->
    <style               > 1024</style> <!-- clip sibl. win.  << 10 -->
    <style               > 2048</style> <!-- disabled         << 11 -->
    <style selected="yes"> 4096</style> <!-- visible          << 12 -->
    <style selected="yes"> 8192</style> <!-- minimize         << 13 -->
    <style               >16384</style> <!-- child window     << 14 -->
    <style               >32768</style> <!-- pop-up           << 15 -->
</windowstyle>
</xsl:template>
<!-- /htmlhelp.def -->

</xsl:stylesheet>
