<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!--                                                          -->
  <!-- define all types of pages, so a new page doesn't         -->
  <!-- trigger the <dependset> to transform *all* xml files     -->
  <!--                                                          -->
  <xsl:include href="moduleindex.xsl"/>
  <xsl:include href="directiveindex.xsl"/>
  <xsl:include href="manualpage.xsl"/>
  <xsl:include href="synopsis.xsl"/>
  <xsl:include href="sitemap.xsl"/>

</xsl:stylesheet>
