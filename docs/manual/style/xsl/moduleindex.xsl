<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!--                              -->
  <!-- Builds the moduleindex page  -->
  <!--                              -->
  <xsl:template match="moduleindex">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

      <body id="module-index">
        <xsl:call-template name="top"/>  

        <div id="preamble">
          <h1>
            <xsl:value-of select="title"/>
          </h1>
          
          <xsl:apply-templates select="summary" />
        </div>
          
        <xsl:call-template name="toplink"/>

        <div class="section">
          <h2>
            <xsl:value-of select="$messages/message[@name='corefeatures']"/>
          </h2>

          <dl>
            <xsl:for-each select="document(modulefilelist/modulefile)/modulesynopsis">
              <xsl:sort select="name"/>

              <xsl:if test="status='MPM' or status='Core'">
                <dt>
                  <a href="{name}.html">
                    <xsl:value-of select="name"/>
                  </a>
                </dt>
                <dd>
                  <xsl:apply-templates select="description"/>
                </dd>
              </xsl:if>
            </xsl:for-each>
          </dl>
        </div>
        <!-- /core section -->

        <xsl:call-template name="toplink"/>

        <div class="section">
          <h2>
            <xsl:value-of select="$messages/message[@name='othermodules']"/>
          </h2>
            
          <dl>
            <xsl:for-each select="document(modulefilelist/modulefile)/modulesynopsis">
              <xsl:sort select="name"/>
                
              <xsl:if test="status!='MPM' and status!='Core'">
                <dt>
                  <a href="{name}.html">
                    <xsl:value-of select="name"/>
                  </a>
                </dt>
                <dd>
                  <xsl:apply-templates select="description"/>
                </dd>
              </xsl:if>
            </xsl:for-each>
          </dl>
        </div>
        <!-- /modules section -->

        <xsl:call-template name="bottom"/>

      </body>
    </html>
  </xsl:template> 
  <!-- /moduleindex -->

</xsl:stylesheet>
