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

<!--        <div id="page-content"> -->
        <div id="preamble">
          <h1>
            <xsl:value-of select="title"/>
          </h1>
          
          <xsl:apply-templates select="summary" />
        </div>
          
<!--
        <div id="quickview">
          <ul id="toc">
            <li>
              <img src="{$path}/images/down.gif" alt="" />
              <xsl:text> </xsl:text>
              <a href="#core">
                <xsl:value-of select="$messages/message[@name='corefeatures']"/>
              </a>
            </li>
            
            <li>
              <img src="{$path}/images/down.gif" alt="" />
              <xsl:text> </xsl:text>
              <a href="#other">
                <xsl:value-of select="$messages/message[@name='othermodules']"/>
              </a>
            </li>

            <li>
              <img src="{$path}/images/down.gif" alt="" />
              <xsl:text> </xsl:text>
              <a href="#obsolete">
                <xsl:value-of select="$messages/message[@name='obsoletemodules']"/>
              </a>
            </li>
          </ul>
        </div>
-->
        <!-- /quickview -->

        <xsl:call-template name="toplink"/>

        <div class="section">
          <h2>
            <a name="core" id="core">
              <xsl:value-of select="$messages/message[@name='corefeatures']"/>
            </a>
          </h2>

          <dl>
            <xsl:for-each select="document(sitemap/category[@id='modules']/modulefilelist/modulefile)/modulesynopsis">
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

<xsl:text>
</xsl:text> <!-- insert line break -->

              </xsl:if>
            </xsl:for-each>
          </dl>
        </div>
        <!-- /core section -->

        <xsl:call-template name="toplink"/>

        <div class="section">
          <h2>
            <a name="other" id="other">
              <xsl:value-of select="$messages/message[@name='othermodules']"/>
            </a>
          </h2>
            
          <dl>
            <xsl:for-each select="document(sitemap/category[@id='modules']/modulefilelist/modulefile)/modulesynopsis">
              <xsl:sort select="name"/>
                
              <xsl:if test="status!='MPM' and status!='Core' and status!='Obsolete'">
                <dt>
                  <a href="{name}.html">
                    <xsl:value-of select="name"/>
                  </a>
                </dt>
                <dd>
                  <xsl:apply-templates select="description"/>
                </dd>

<xsl:text>
</xsl:text> <!-- insert line break -->

              </xsl:if>
            </xsl:for-each>
          </dl>
        </div>
        <!-- /modules section -->

<!--
        <xsl:call-template name="toplink"/>

        <div class="section">
          <h2>
            <a name="obsolete" id="obsolete">
              <xsl:value-of select="$messages/message[@name='obsoletemodules']"/>
            </a>
          </h2>
            
          <dl>
            <xsl:for-each select="document(sitemap/category[@id='modules']/modulefilelist/modulefile)/modulesynopsis">
              <xsl:sort select="name"/>
                
              <xsl:if test="status='Obsolete'">
                <dt>
                  <a href="obs_{name}.html">
                    <xsl:value-of select="name"/>
                  </a>
                </dt>
                <dd>
                  <xsl:if test="hint">
                    <em>
                      <xsl:text>(</xsl:text>
                      <xsl:apply-templates select="hint"/>
                      <xsl:text>)</xsl:text>
                    </em>
                    <br />
                  </xsl:if>

                  <xsl:apply-templates select="description"/>
                </dd>

<xsl:text>
</xsl:text>

              </xsl:if>
            </xsl:for-each>
          </dl>
        </div>
-->
        <!-- /obsolete section -->

<!--        </div> <!- /page-content -->

        <xsl:call-template name="bottom"/>

      </body>
    </html>
  </xsl:template> 
  <!-- /moduleindex -->

</xsl:stylesheet>
