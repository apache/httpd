<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="html" encoding="iso-2022-jp" indent="no"/>

<!-- Read the localized messages from the specified language file -->
<xsl:variable name="messages" select="document('ja.xml')/messages"/>

<!-- Now get the real guts of the stylesheet -->
<xsl:include href="common.xsl"/>

</xsl:stylesheet>
