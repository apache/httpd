/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef WIN32

/* main_win32.c - Apache executable stub file for Win32
 * This file's purpose in life is to load, and call the
 * "real" main function, apache_main(), located in ApacheCore.dll
 *
 * This was done because having the main() function in a DLL,
 * although Win32 allows it, seemed wrong. Also, MSVC++ won't
 * link an executable without at least one object file. This
 * satistifies that requirement.
 */

__declspec(dllexport) int apache_main(int argc, char *argv[]);

int main(int argc, char *argv[]) 
{
    return apache_main(argc, argv);
}

#endif /* WIN32 */
