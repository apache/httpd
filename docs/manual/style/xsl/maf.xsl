<?xml version="1.0"?>

<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<!DOCTYPE xsl:stylesheet [
    <!ENTITY lf SYSTEM "util/lf.xml">
]>

<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output
  method="xml"
  encoding="utf-8"
  indent="no"
/>

<xsl:param name="date" select="false()" />
<xsl:param name="lang" />

<!-- ==================================================================== -->
<!-- <indexpage>                                                          -->
<!-- build rdf description                                                -->
<!-- ==================================================================== -->
<xsl:template match="/indexpage">
<RDF:RDF xmlns:MAF="http://maf.mozdev.org/metadata/rdf#"
             xmlns:NC="http://home.netscape.com/NC-rdf#"
             xmlns:RDF="http://www.w3.org/1999/02/22-rdf-syntax-ns#">&lf;
  <RDF:Description RDF:about="urn:root">&lf;
    <MAF:originalurl RDF:resource="" />&lf;
    <MAF:title RDF:resource="{title}" />&lf;
    <xsl:if test="$date">
        <MAF:archivetime RDF:resource="{$date}" />&lf;
    </xsl:if>
    <MAF:indexfilename RDF:resource="index.html" />&lf;
  </RDF:Description>&lf;
</RDF:RDF>&lf;
</xsl:template>
<!-- /indexpage -->

</xsl:stylesheet>
