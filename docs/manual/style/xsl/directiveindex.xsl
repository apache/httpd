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

<!-- ==================================================================== -->
<!-- <directiveindex>                                                     -->
<!-- Builds the directive index page                                      -->
<!-- ==================================================================== -->
<xsl:template match="directiveindex">
<html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
    <xsl:call-template name="head"/>&lf;

    <body id="directive-index">
        <xsl:call-template name="top"/>

        <xsl:variable name="directives"
            select="document(modulefilelist/modulefile)
                        /modulesynopsis[status!='Obsolete']
                        /directivesynopsis[not(@location)]" />

        <!-- collect the start letters -->
        <xsl:variable name="start-letters">
            <xsl:call-template name="directive-startletters">
                <xsl:with-param name="directives" select="$directives" />
            </xsl:call-template>
        </xsl:variable>

        <div id="preamble">
            <h1>
                <xsl:value-of select="title" />
            </h1>&lf;

            <xsl:call-template name="langavail" />&lf;

            <xsl:apply-templates select="summary" />&lf;

            <!-- letter bar -->
            <p class="letters">
                <xsl:call-template name="letter-bar">
                    <xsl:with-param name="letters" select="$start-letters" />
                    <xsl:with-param name="first" select="true()" />
                </xsl:call-template>
            </p>&lf; <!-- /.letters -->
        </div>&lf; <!-- /preamble -->

        <div id="directive-list">
            <ul>&lf;
                <xsl:call-template name="dindex-of-letter">
                    <xsl:with-param name="letters-todo"
                        select="$start-letters" />
                    <xsl:with-param name="directives" select="$directives" />
                </xsl:call-template>
            </ul>
        </div>&lf; <!-- /#directive-list -->

        <xsl:call-template name="bottom" />&lf;
    </body>
</html>
</xsl:template>
<!-- /directiveindex -->


<!-- ==================================================================== -->
<!-- the working horse. builds list items of all directives starting with -->
<!-- one letter when done, it calls itself to catch the next letter       -->
<!-- ==================================================================== -->
<xsl:template name="dindex-of-letter">
<xsl:param name="letters-todo" />
<xsl:param name="directives" />

<xsl:variable name="letter" select="substring($letters-todo, 1, 1)"/>

<xsl:for-each
    select="$directives
                [$letter = translate(substring(normalize-space(name), 1, 1),
                                     $lowercase, $uppercase)]">
<xsl:sort select="name" />
    <li>
        <a href="{../name}.html#{translate(name, $uppercase, $lowercase)}">
            <xsl:if test="position() = 1">
                <xsl:attribute name="id">
                    <xsl:value-of select="$letter" />
                </xsl:attribute>
                <xsl:attribute name="name">
                    <xsl:value-of select="$letter" />
                </xsl:attribute>
            </xsl:if>

            <xsl:if test="@type = 'section'">&lt;</xsl:if>
            <xsl:value-of select="name" />
            <xsl:if test="@type = 'section'">&gt;</xsl:if>
        </a>
    </li>&lf;
</xsl:for-each>

<!-- call next letter, if there is -->
<xsl:if test="string-length($letters-todo) &gt; 1">
    <xsl:call-template name="dindex-of-letter">
        <xsl:with-param name="letters-todo"
            select="substring($letters-todo, 2)" />
        <xsl:with-param name="directives" select="$directives" />
    </xsl:call-template>
</xsl:if>

</xsl:template>
<!-- /dindex-of-letter -->

</xsl:stylesheet>
