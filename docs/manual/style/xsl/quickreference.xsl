<?xml version="1.0"?><!--
/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002-2004 The Apache Software Foundation.  All rights
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
<!-- <quickreference>                                                     -->
<!-- Builds the directive quickreference page                             -->
<!-- ==================================================================== -->
<xsl:template match="quickreference">
<html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
    <xsl:call-template name="head"/>&lf;

    <body id="directive-index">&lf;
        <xsl:call-template name="top"/>&lf;

        <div id="preamble">
            <h1>
                <xsl:value-of select="title" />
            </h1>&lf;

            <xsl:call-template name="langavail" />&lf;

            <xsl:apply-templates select="summary" />
        </div>&lf; <!-- /#preamble -->

        <div id="directive-ref">
            <xsl:variable name="directives"
                select="document(modulefilelist/modulefile)
                        /modulesynopsis/directivesynopsis[not(@location)]" />

            <xsl:variable name="start-letters">
                <xsl:call-template name="directive-startletters">
                    <xsl:with-param name="directives" select="$directives" />
                </xsl:call-template>
            </xsl:variable>

            <table id="legend">&lf;
            <tr>
                <td class="letters">
                    <span>
                        <xsl:call-template name="letter-bar">
                            <xsl:with-param name="letters"
                                select="$start-letters" />
                            <xsl:with-param name="first" select="true()" />
                        </xsl:call-template>
                    </span>
                </td>&lf;
                <td>
                    <xsl:apply-templates select="legend/table[position()=1]" />
                </td>&lf;
                <td>
                    <xsl:apply-templates select="legend/table[position()=2]" />
                </td>
            </tr>&lf;
            </table>&lf;

            <table class="qref">&lf;
            <xsl:call-template name="reference-of-letter">
                <xsl:with-param name="letters-todo" select="$start-letters" />
                <xsl:with-param name="offset" select="number(0)" />
                <xsl:with-param name="directives" select="$directives" />
            </xsl:call-template>
            </table>
        </div>&lf; <!-- /#directive-ref -->

        <xsl:call-template name="bottom"/>&lf;
    </body>
</html>
</xsl:template>
<!-- /quickreference -->


<!-- ==================================================================== -->
<!-- the working horse. builds rows of all directives starting with one   -->
<!-- letter when done, it calls itself to catch the next letter           -->
<!-- ==================================================================== -->
<xsl:template name="reference-of-letter">
<xsl:param name="letters-todo" />
<xsl:param name="offset" />
<xsl:param name="directives" />

<xsl:variable name="letter" select="substring($letters-todo, 1, 1)" />

<xsl:for-each
    select="$directives[$letter=translate(substring(normalize-space(name), 1,1),
                                          $lowercase,$uppercase)]">
<xsl:sort select="name" />

    <tr>
        <xsl:if test="position() mod 2 = $offset">
            <xsl:attribute name="class">odd</xsl:attribute>
        </xsl:if>

        <td>
            <a href="{../name}.html#{translate(name, $uppercase, $lowercase)}">
                <xsl:if test="position()=1">
                    <xsl:attribute name="id">
                        <xsl:value-of select="$letter" />
                    </xsl:attribute>
                    <xsl:attribute name="name">
                        <xsl:value-of select="$letter" />
                    </xsl:attribute>
                </xsl:if>

                <xsl:apply-templates select="syntax" />
            </a>
        </td>
        <td>
            <!-- if the default value contains (at least) one <br />, -->
            <!-- this probably means that a short explanation follows -->
            <!-- the actual default value. We cut off the string      -->
            <!-- after the <br /> so it will not be shown here.       -->
            <!-- (add the + character instead)                        -->
            <xsl:variable name="default">
                <xsl:choose>
                <xsl:when test="count(default[count(br) &gt; 0]) &gt; 0">
                    <xsl:value-of
                        select="default/child::node()
                                [count(preceding-sibling::*) = 0]" />
                </xsl:when>
                <xsl:otherwise>
                    <xsl:value-of select="default"/>
                </xsl:otherwise>
                </xsl:choose>
            </xsl:variable>

            <xsl:value-of select="substring(substring-after(concat($default,
                                  ' '), name),1,20)" />
            <xsl:if test="string-length(substring-after(concat($default, ' '),
                              name)) &gt; 20
                          or count(default[count(br) &gt; 0]) &gt; 0">
                <xsl:text> +</xsl:text>
            </xsl:if>
        </td>
        <td>
            <xsl:if test="contextlist/context
                          [normalize-space(.)='server config']">s</xsl:if>
            <xsl:if test="contextlist/context
                          [normalize-space(.)='virtual host']">v</xsl:if>
            <xsl:if test="contextlist/context
                          [normalize-space(.)='directory']">d</xsl:if>
            <xsl:if test="contextlist/context
                          [normalize-space(.)='.htaccess']">h</xsl:if>
        </td>
        <td>
            <xsl:choose>
            <xsl:when test="../status='Base'">B</xsl:when>
            <xsl:when test="../status='MPM'">M</xsl:when>
            <xsl:when test="../status='Core'">C</xsl:when>
            <xsl:when test="../status='Extension'">E</xsl:when>
            <xsl:when test="../status='Experimental'">X</xsl:when>
            </xsl:choose>
        </td>
    </tr>
    <tr>
        <xsl:if test="position() mod 2 = $offset">
            <xsl:attribute name="class">odd</xsl:attribute>
        </xsl:if>

        <td colspan="4" class="descr">
            <xsl:choose>
            <xsl:when test="string-length(normalize-space(description)) &gt; 0">
                <xsl:apply-templates select="description"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:text>-</xsl:text>
            </xsl:otherwise>
            </xsl:choose>
        </td>
    </tr>&lf;
</xsl:for-each> <!-- /directives -->

<!-- call next letter, if there is -->
<xsl:if test="string-length($letters-todo) &gt; 1">
    <xsl:call-template name="reference-of-letter">
        <xsl:with-param name="letters-todo"
            select="substring($letters-todo, 2)" />
        <xsl:with-param name="offset"
            select="(count($directives[$letter=translate(substring(
                    normalize-space(name), 1, 1), $lowercase, $uppercase)])
                    + $offset) mod 2" />
        <xsl:with-param name="directives" select="$directives" />
    </xsl:call-template>
</xsl:if>
</xsl:template>
<!-- /reference-of-letter -->

</xsl:stylesheet>
