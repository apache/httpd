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
    <!ENTITY lf SYSTEM "util/lf.xml">
]>

<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="">

<xsl:output 
  method="text"
  encoding="utf-8"
  indent="no"
/>

<!-- create nodeset for referencing later                                 -->
<xsl:variable name="design" select="document('')/xsl:stylesheet
                                    /xsl:template[@name='designations']/item" />

<!-- Constants used for case translation -->
<xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'" />
<xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

<!-- ==================================================================== -->
<!-- <metafile>                                                           -->
<!-- build typemap                                                        -->
<!-- ==================================================================== -->
<xsl:template match="/metafile">
<xsl:apply-templates select="variants/variant" />
</xsl:template>
<!-- /metafile -->

<!-- ==================================================================== -->
<!-- <variant>                                                            -->
<!-- ==================================================================== -->
<xsl:template match="variant">
<xsl:variable name="lang" select="translate(., $uppercase, $lowercase)" />
<xsl:if test="not($design[translate(@lang, $uppercase, $lowercase) = $lang])">
    <xsl:message terminate="yes">
FATAL: missing designation data for language <xsl:value-of select="." />.
The XSLT-Stylesheet won't work without modification.
    </xsl:message>
</xsl:if>

<xsl:text>URI: </xsl:text>
<xsl:value-of select="/metafile/basename" />
<xsl:text>.html</xsl:text>
<xsl:value-of select="$design[translate(@lang, $uppercase, $lowercase)
                              = $lang]" />&lf;

<xsl:text>Content-Language: </xsl:text>
<xsl:value-of select="$design[translate(@lang, $uppercase, $lowercase)
                              = $lang]/@lang" />&lf;

<xsl:text>Content-type: text/html; charset=</xsl:text>
<xsl:value-of select="$design[translate(@lang, $uppercase, $lowercase)
                              = $lang]/@charset" />&lf;

<xsl:if test="position() != last()">&lf;</xsl:if>
</xsl:template>
<!-- /variant -->

<!-- ==================================================================== -->
<!-- do NOT call this template, it's referenced automagically via         -->
<!-- document() function and acts as simple data container.               -->
<!-- ==================================================================== -->
<xsl:template name="designations">
<item lang="de"    charset="ISO-8859-1" >.de</item>
<item lang="en"    charset="ISO-8859-1" >.en</item>
<item lang="fr"    charset="ISO-8859-1" >.fr</item>
<item lang="ja"    charset="ISO-2022-JP">.ja.jis</item>
<item lang="ko"    charset="EUC-KR"     >.ko.euc-kr</item>
<item lang="ru"    charset="KOI8-R"     >.ru.koi8-r</item>
<item lang="zh-CN" charset="GB2312"     >.zh-cn.gb2312</item>
</xsl:template>

</xsl:stylesheet>
