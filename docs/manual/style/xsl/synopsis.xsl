<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!--                                                    -->
  <!-- <modulesynopsis>                                   -->
  <!-- Process an entire document into an HTML page       -->
  <!--                                                    -->
  <xsl:template match="modulesynopsis">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

      <body>
        <xsl:call-template name="top"/>

        <div id="page-content">
          <div id="preamble">
            <h1>
              <xsl:value-of select="$messages/message[@name='apachemodule']"/>
              <xsl:text> </xsl:text> 
              <xsl:value-of select="name"/>
            </h1>

            <!-- Description and module-headers -->
            <table class="module">
              <tr>
                <th>
                  <a href="module-dict.html#Description">
                    <xsl:value-of select="$messages/message[@name='description']"/>:
                  </a>
                </th>
                <td>
                  <xsl:apply-templates select="description"/>
                </td>
              </tr>

              <tr>
                <th>
                  <a href="module-dict.html#Status">
                    <xsl:value-of select="$messages/message[@name='status']"/>:
                  </a>
                </th>
                <td>
                  <xsl:value-of select="status"/>
                </td>
              </tr>

              <xsl:if test="identifier">
              <tr>
                <th>
                  <a href="module-dict.html#ModuleIdentifier">
                    <xsl:value-of select="$messages/message[@name='moduleidentifier']"/>:
                  </a> 
                </th>
                <td>
                  <xsl:value-of select="identifier"/>
                </td>
              </tr>
              </xsl:if>

              <xsl:if test="sourcefile">
              <tr>
                <th>
                  <a href="module-dict.html#SourceFile">
                    <xsl:value-of select="$messages/message[@name='sourcefile']"/>:
                  </a> 
                </th>
                <td>
                  <xsl:value-of select="sourcefile"/>
                </td>
              </tr>
              </xsl:if>

              <xsl:if test="compatibility">
              <tr>
                <th>
                  <a href="module-dict.html#Compatibility">
                    <xsl:value-of select="$messages/message[@name='compatibility']"/>:
                  </a>
                </th>
                <td>
                  <xsl:value-of select="compatibility"/>
                </td>
              </tr>
              </xsl:if>
            </table>

            <!-- Summary of module features/usage (1 to 3 paragraphs, optional) -->
            <xsl:if test="summary">
              <h3>
                <xsl:value-of select="$messages/message[@name='summary']"/>
              </h3>

              <xsl:apply-templates select="summary"/>
            </xsl:if>
          </div> <!-- /preamble -->

          <div id="quickview">

            <!-- Index of directives, automatically generated from
                 directivesynopsis/name -->
            <h3 class="directives">
              <xsl:value-of select="$messages/message[@name='directives']"/>
            </h3>

            <xsl:if test="directivesynopsis">
              <ul id="toc">
                <xsl:for-each select="directivesynopsis">
                  <xsl:sort select="name"/>
                  <xsl:variable name="lowername" select="translate(name, $uppercase, $lowercase)"/>

                  <xsl:if test="not(@location)">
                    <li>
                      <img src="{$path}/images/down.gif" alt="" />
                      <xsl:text> </xsl:text>
                      <a href="#{$lowername}">
                        <xsl:if test="@type='section'">&lt;</xsl:if>
                        <xsl:value-of select="name"/>
                        <xsl:if test="@type='section'">&gt;</xsl:if>
                      </a>
                    </li>
                  </xsl:if>

                  <xsl:if test="@location">
                    <xsl:variable name="lowerlocation" select="translate(@location, $uppercase, $lowercase)"/>

                    <li>
                      <img src="{$path}/images/right.gif" alt="" />
                      <xsl:text> </xsl:text>
                      <a href="{$lowerlocation}.html#{$lowername}">
                        <xsl:if test="@type='section'">&lt;</xsl:if>
                        <xsl:value-of select="name"/>
                        <xsl:if test="@type='section'">&gt;</xsl:if>
                      </a>
                    </li>
                  </xsl:if>
                </xsl:for-each>
              </ul> <!-- /toc -->
            </xsl:if>

            <xsl:if test="not(directivesynopsis)">
              <p>
                <xsl:value-of select="$messages/message[@name='nodirectives']"/>
              </p>
            </xsl:if>

            <xsl:if test="section">
              <h3>
                <xsl:value-of select="$messages/message[@name='topics']"/>
              </h3>
              <ul id="topics">
                <xsl:apply-templates select="section" mode="index"/>
              </ul>
            </xsl:if>

            <xsl:if test="seealso">
	      <h3>
                  <xsl:value-of select="$messages/message[@name='seealso']"/>
              </h3>
            
              <ul class="seealso">
                <xsl:for-each select="seealso">
                  <li>
                    <xsl:apply-templates/>
                  </li>
                </xsl:for-each>
              </ul>
            </xsl:if>

          </div> <!-- /quickview -->

          <!-- Sections of documentation about the module as a whole -->
          <xsl:apply-templates select="section"/>

          <!-- Directive documentation -->
          <xsl:apply-templates select="directivesynopsis">
            <xsl:sort select="name"/>
          </xsl:apply-templates>

        </div> <!-- /page-content -->

        <xsl:call-template name="bottom"/>
      </body>
    </html>
  </xsl:template>
  <!-- /modulesynopsis -->


  <!--                                                            -->
  <!--    Directivesynopsis                                       -->
  <!--                                                            -->
  <xsl:template match="directivesynopsis">
    <xsl:if test="not(@location)">

      <xsl:call-template name="toplink"/>

      <div class="directive-section">
        <xsl:variable name="lowername" select="translate(name, $uppercase, $lowercase)"/>

        <!-- Directive heading gets both mixed case and lowercase anchors,
             and includes lt/gt only for "section" directives -->
        <h2>
          <a id="{name}" name="{name}">
            <xsl:if test="@type='section'">&lt;</xsl:if>
            <xsl:value-of select="name"/>
            <xsl:if test="@type='section'">&gt;</xsl:if>
          </a>
          <xsl:text> </xsl:text>
          <a id="{$lowername}" name="{$lowername}">
            <xsl:value-of select="$messages/message[@name='directive']"/>
          </a>
        </h2>

        <!-- Directive header -->
        <table class="directive">
          <tr>
            <th>
              <a href="directive-dict.html#Description">
                <xsl:value-of select="$messages/message[@name='description']"/>: 
              </a>
            </th>
            <td>
              <xsl:value-of select="description"/>
            </td>
          </tr>

          <tr>
            <th>
              <a href="directive-dict.html#Syntax">
                <xsl:value-of select="$messages/message[@name='syntax']"/>:
              </a> 
            </th>
            <td>
              <xsl:apply-templates select="syntax"/>
            </td>
          </tr>

          <xsl:if test="default">
          <tr>
            <th>
              <a href="directive-dict.html#Default">
                <xsl:value-of select="$messages/message[@name='default']"/>: 
              </a> 
            </th>
            <td>
              <code>
                <xsl:value-of select="default"/>
              </code>
            </td>
          </tr>
          </xsl:if>

          <tr>
            <th>
              <a href="directive-dict.html#Context">
                <xsl:value-of select="$messages/message[@name='context']"/>:
              </a> 
            </th>
            <td>
              <xsl:apply-templates select="contextlist"/>
            </td>
          </tr>

          <xsl:if test="override">
          <tr>
            <th>
              <a href="directive-dict.html#Override">
                <xsl:value-of select="$messages/message[@name='override']"/>:
              </a> 
            </th>
            <td>
              <xsl:value-of select="override"/>
            </td>
          </tr>
          </xsl:if>

          <tr>
            <th>
              <a href="directive-dict.html#Status">
                <xsl:value-of select="$messages/message[@name='status']"/>:
              </a> 
            </th>
            <td>
              <xsl:value-of select="../status"/>
            </td>
          </tr>

          <tr>
            <th>
              <a href="directive-dict.html#Module">
                <xsl:value-of select="$messages/message[@name='module']"/>:
              </a> 
            </th>
            <td>
              <xsl:if test="modulelist">
                <xsl:apply-templates select="modulelist"/>
              </xsl:if>

              <xsl:if test="not(modulelist)">
                <xsl:value-of select="../name"/>
              </xsl:if>
            </td>
          </tr>

          <xsl:if test="compatibility">
          <tr>
            <th>
              <a href="directive-dict.html#Compatibility">
                <xsl:value-of select="$messages/message[@name='compatibility']"/>:
              </a> 
            </th>
            <td>
              <xsl:value-of select="compatibility"/>
            </td>
          </tr>
          </xsl:if>
        </table>

        <xsl:apply-templates select="usage"/>

        <xsl:if test="seealso">
          <h3>
            <xsl:value-of select="$messages/message[@name='seealso']"/>
          </h3>

          <ul>
            <xsl:for-each select="seealso">
              <li>
                <xsl:apply-templates/>
              </li>
            </xsl:for-each>
          </ul>
        </xsl:if>

      </div> <!-- /directive-section -->
    </xsl:if>
  </xsl:template>
  <!-- /directivesynopsis -->


  <!--                                                    -->
  <!-- <contextlist>                                      -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="contextlist">
    <xsl:apply-templates select="context"/>
  </xsl:template> 
  <!-- /contextlist -->


  <!--                                                    -->
  <!-- <context>                                          -->
  <!-- Each entry is separeted with a comma               -->
  <!--                                                    -->
  <xsl:template match="context">
    <xsl:value-of select="."/>
    <xsl:if test="position() != last()">
      <xsl:text>, </xsl:text>
    </xsl:if>
  </xsl:template> 
  <!-- /context -->


  <!--                                                    -->
  <!-- <modulelist>                                       -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="modulelist">
    <xsl:for-each select="module">
      <xsl:call-template name="module"/>
      <xsl:if test="position() != last()">
        <xsl:text>, </xsl:text>
      </xsl:if>
    </xsl:for-each>
  </xsl:template> 
  <!-- /modulelist -->

</xsl:stylesheet>
