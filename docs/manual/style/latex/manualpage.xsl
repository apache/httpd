<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

<xsl:template match="manualpage">

<xsl:call-template name="section-title"/>

<xsl:apply-templates select="summary"/>

<xsl:call-template name="seealso"/>

<xsl:apply-templates select="section"/>
</xsl:template>

</xsl:stylesheet>