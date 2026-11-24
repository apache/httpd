<?xml version="1.0"?>
<!DOCTYPE overrideindex SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1793923 -->
<!-- Spanish Translation: Arturo Bernal <arturobernalg@gmail.com> -->

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

<overrideindex metafile="overrides.xml.meta">
  <title>Índice de clases de anulación para .htaccess</title>
  <summary>
    <p>
      Este es un índice de las directivas permitidas en archivos .htaccess para
      los distintos valores de <directive module="core">AllowOverride</directive>,
      organizado por clase. Su propósito es ayudar a los administradores del servidor a
      verificar los privilegios que están concediendo a los usuarios de .htaccess. Para una
      descripción general de cómo funciona .htaccess, consulte el
      <a href="../howto/htaccess.html">tutorial de .htaccess</a>.
    </p>

    <p>
      Para determinar el conjunto de directivas que la configuración de su servidor permite
      usar a los usuarios de .htaccess:
    </p>

    <ol>
      <li>Empiece con el conjunto de directivas de <code>AllowOverrideList</code>
      para el directorio en cuestión. (Por defecto, está establecido en
      <code>None</code>.)</li>
      <li>Busque el valor de <code>AllowOverride</code> para el directorio en
      cuestión. (Por defecto, está establecido en <code>None</code>.) Hay dos
      casos especiales:
        <ol>
          <li>Si su valor de <code>AllowOverride</code> es <code>All</code>,
          añada a la lista todas las directivas listadas en esta página.</li>
          <li>Si su valor de <code>AllowOverride</code> es <code>None</code>,
          ha terminado. Solo se permitirán las directivas de <code>AllowOverrideList</code>
          (si hay alguna).</li>
        </ol>
      </li>
      <li>Para cada clase de anulación listada en <code>AllowOverride</code>, busque
      el conjunto de directivas correspondiente más abajo y añádalas a la lista.</li>
      <li>Por último, añada el conjunto de directivas que siempre se permiten
      en .htaccess (están listadas en la
      <a href="#override-all">sección All</a>, a continuación).</li>
    </ol>

    <p>
      Varias de las clases de anulación son muy potentes y dan a los usuarios
      de .htaccess un gran control sobre el servidor. Para un enfoque más estricto,
      establezca <code>AllowOverride None</code> y use
      <directive module="core">AllowOverrideList</directive> para especificar
      la lista exacta de directivas que los usuarios de .htaccess pueden usar.
    </p>
  </summary>

  <!--
    Provide one overridesummary element for each Override type. The content will
    be sucked into the relevant section on the override index page.
  -->

  <overridesummary class="All">
    <p>
      Las siguientes directivas se permiten en cualquier archivo .htaccess, siempre que
      las anulaciones estén activadas en la configuración del servidor.
    </p>
  </overridesummary>

  <overridesummary class="AuthConfig">
    <p>
      Las siguientes directivas se permiten en archivos .htaccess cuando está vigente
      <code>AllowOverride AuthConfig</code>. Dan a los usuarios de .htaccess
      control sobre los métodos de autenticación y autorización que se
      aplican a sus subárboles de directorios, incluidas varias directivas de utilidad
      relacionadas con el manejo de sesiones y la configuración de TLS.
    </p>
  </overridesummary>

  <overridesummary class="FileInfo">
    <p>
      Las siguientes directivas se permiten en archivos .htaccess cuando está vigente
      <code>AllowOverride FileInfo</code>. Dan a los usuarios de .htaccess
      un amplio control sobre las respuestas y los metadatos proporcionados por el
      servidor.
    </p>
  </overridesummary>

  <overridesummary class="Indexes">
    <p>
      Las siguientes directivas se permiten en archivos .htaccess cuando está vigente
      <code>AllowOverride Indexes</code>. Permiten a los usuarios de .htaccess
      controlar aspectos de las páginas de índice de directorio proporcionadas por el
      servidor, incluida la generación de autoindex.
    </p>
  </overridesummary>

  <overridesummary class="Limit">
    <p>
      Las siguientes directivas se permiten en archivos .htaccess cuando está vigente
      <code>AllowOverride Limit</code>. Esta clase de anulación, extremadamente limitada,
      permite principalmente el uso de las directivas de autorización heredadas
      proporcionadas por <module>mod_access_compat</module>.
    </p>
  </overridesummary>

  <overridesummary class="Options">
    <p>
      Las siguientes directivas se permiten en archivos .htaccess cuando está vigente
      <code>AllowOverride Options</code>. Dan a los usuarios de .htaccess
      acceso a <code>Options</code> y directivas similares, así como a
      directivas que controlan la cadena de filtros.
    </p>
  </overridesummary>

  <!--
    This is the error message for when a directive shows up in a section that
    has no explicit overridesummary above.
  -->
  <overridesummary fallback="yes">
    <p><em>
    [Esta sección no tiene descripción. Es posible que la documentación esté
    incompleta, o que las directivas aquí listadas tengan un tipo de Override
    incorrecto o mal escrito. Considere reportarlo en la
    <a href="#comments_section">sección de comentarios</a>.]
    </em></p>
  </overridesummary>
</overrideindex>
