<?xml version="1.0"?><!--
/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002-2003 The Apache Software Foundation.  All rights
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
    <!ENTITY lf SYSTEM "util/lf.xml">
]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

<!-- If we use document() in the context of this xsl file, the contextual -->
<!-- CWD is the xsl file containing directory. $basedir reflects the      -->
<!-- manual root for that case.                                           -->
<xsl:variable name="basedir" select="'../../'" />

<!-- ==================================================================== -->
<!-- <sitemap>                                                            -->
<!-- Process an entire document into an HTML page                         -->
<!-- ==================================================================== -->
<xsl:template match="/sitemap">
<html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
    <xsl:call-template name="head" />&lf;

    <body id="manual-page">&lf;
        <xsl:call-template name="top" />&lf;

        <div id="page-content">
            <div id="preamble">        
                <h1>
                    <xsl:value-of select="title" />
                </h1>&lf;

                <xsl:call-template name="langavail" />&lf;

                <xsl:apply-templates select="summary" />
            </div>&lf; <!-- /#preamble -->
          
            <xsl:if test="(not($is-chm) and count(category) &gt; 1) or seealso">
                <div id="quickview">
                    <xsl:if test="not($is-chm) and count(category) &gt; 1">
                        <ul id="toc">&lf;
                        <xsl:for-each select="category">
                            <xsl:choose>
                            <xsl:when test="@id">
                                <li>
                                    <img src="{$path}/images/down.gif" alt="" />
                                    <xsl:text> </xsl:text>
                                    <a href="#{@id}">
                                        <xsl:apply-templates
                                            select="title" mode="print" />
                                    </a>
                                </li>&lf;
                            </xsl:when>
                            <xsl:otherwise>
                                <li>
                                    <img src="{$path}/images/down.gif" alt="" />
                                    <xsl:text> </xsl:text>
                                    <xsl:apply-templates
                                        select="title" mode="print" />
                                </li>&lf;
                            </xsl:otherwise>
                            </xsl:choose>
                        </xsl:for-each>
                        </ul>&lf;
                    </xsl:if>

                    <xsl:if test="seealso">
                        <h3>
                            <xsl:value-of select="$messages/message
                                                  [@name='seealso']" />
                        </h3>&lf;

                        <ul class="seealso">&lf;
                        <xsl:for-each select="seealso">
                            <li>
                                <xsl:apply-templates />
                            </li>&lf;
                        </xsl:for-each>
                        </ul>&lf;
                    </xsl:if>
	            </div>&lf; <!-- /#quickview -->
            </xsl:if> <!-- have sidebar -->

            <xsl:apply-templates select="category" />
        </div>&lf; <!-- /#page-content -->

        <xsl:call-template name="bottom" />&lf;
    </body>
</html>
</xsl:template>
<!-- /sitemap -->
  

<!-- ==================================================================== -->
<!-- category/page                                                        -->
<!-- ==================================================================== -->
<xsl:template match="sitemap/category/page">
<li>
    <xsl:if test="@separate='yes'">
        <xsl:attribute name="class">separate</xsl:attribute>
    </xsl:if>

    <xsl:choose>
    <xsl:when test="@href">
        <a href="{@href}">
            <xsl:call-template name="helper.uri.fix">
                <xsl:with-param name="uri" select="@href" />
            </xsl:call-template>
            <xsl:value-of select="." />
        </a>
    </xsl:when>
    <xsl:otherwise>
        <xsl:value-of select="." />
    </xsl:otherwise>
    </xsl:choose>
</li>&lf;
</xsl:template>
<!-- /category/page -->


<!-- ==================================================================== -->
<!-- Process a sitemap category                                           -->
<!-- ==================================================================== -->
<xsl:template match="sitemap/category">
<xsl:call-template name="toplink" />&lf;

<div class="section">
    <!-- Category title -->
    <h2>
        <xsl:choose>
        <xsl:when test="@id">
            <a id="{@id}" name="{@id}">
                <xsl:apply-templates select="title" mode="print" />
            </a>
        </xsl:when>
        <xsl:otherwise>
            <xsl:apply-templates select="title" mode="print" />
        </xsl:otherwise>
        </xsl:choose>
    </h2>&lf;

    <!-- category body -->
    <ul>
        <xsl:apply-templates select="page" />
    </ul>
      
    <!-- optional ... -->
    <xsl:apply-templates select="modulefilelist" />&lf;
</div> <!-- /.section -->
</xsl:template>
<!-- /category -->


<!-- ==================================================================== -->
<!-- category/modulefilelist                                              -->
<!-- insert module list into sitemap                                      -->
<!-- ==================================================================== -->
<xsl:template match="sitemap/category/modulefilelist">
<xsl:variable name="translist">
    <xsl:text>-</xsl:text>
    <xsl:for-each select="modulefile">
        <xsl:variable name="current"
            select="document(concat($basedir,'mod/',.))/modulesynopsis" />
   
        <xsl:text> </xsl:text>
        <xsl:value-of select="$current/name" />
        <xsl:text> </xsl:text>
        <xsl:call-template name="module-translatename">
            <xsl:with-param name="name" select="$current/name" />
        </xsl:call-template>
        <xsl:text> -</xsl:text>
    </xsl:for-each>
</xsl:variable>

<ul>
<li>
    <a href="mod/core.html">
        <xsl:value-of select="$messages/message[@name='apachecore']" />
    </a>
</li>&lf;
<li>
    <a href="mod/mpm_common.html">
        <xsl:value-of select="$messages/message[@name='apachempmcommon']" />
    </a>
</li>&lf;

<xsl:for-each select="modulefile">
<xsl:sort select="substring-before(substring-after($translist, concat('- ',
    document(concat($basedir,'mod/',.))/modulesynopsis/name, ' ')), ' -')" />

    <xsl:variable name="current" select="document(concat($basedir, 'mod/', .))
                                         /modulesynopsis" />

    <xsl:if test="$current/status='MPM' and $current/name!='mpm_common'">
        <xsl:variable name="name" select="substring-before(substring-after(
                        $translist, concat('- ', $current/name, ' ')), ' -')" />

        <li>
            <a href="mod/{$current/name}.html">
                <xsl:value-of select="$messages/message[@name='apachempm']" />
                <xsl:text> </xsl:text>
                <xsl:value-of select="$name" />
            </a>
        </li>&lf;
    </xsl:if>
</xsl:for-each>
</ul>

<ul>
<xsl:for-each select="modulefile">
<xsl:sort select="substring-before(substring-after($translist, concat('- ',
    document(concat($basedir,'mod/',.))/modulesynopsis/name, ' ')), ' -')"/>

    <xsl:variable name="current" select="document(concat($basedir,'mod/',.))
                                         /modulesynopsis" />

    <xsl:if test="$current/status!='MPM' and $current/status!='Core'">
        <li>
            <a href="mod/{$current/name}.html">
                <xsl:value-of select="$messages/message[@name='apachemodule']"/>
                <xsl:text> </xsl:text>
                <xsl:value-of select="$current/name"/>
            </a>
        </li>&lf;
    </xsl:if>
</xsl:for-each>
</ul>
</xsl:template>
<!-- /category/modulefilelist -->

</xsl:stylesheet>
