<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template name="module-translatename">
<xsl:param name="name"/>

  <xsl:variable name="sname" select="translate($name,$lowercase,$uppercase)"/>

  <xsl:choose>
    <xsl:when test="starts-with($sname,'MOD_') or starts-with($sname,'MPM_')">
      <xsl:value-of select="substring($name, 5)"/>
    </xsl:when>

    <xsl:when test="starts-with($sname,'MPMT_')">
      <xsl:value-of select="substring($name, 6)"/>
    </xsl:when>

    <xsl:otherwise>
      <xsl:value-of select="$name"/>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>
<!-- /module-translatename -->

</xsl:stylesheet>
