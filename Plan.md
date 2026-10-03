October 14 – 27
Set up WSL + Ubuntu development environment

Learn GitHub workflow and LaTeX basics

Fork and clone the Apache httpd ECH repository

Notes

Verify compiler, build tools, and version control setup

October 28 – November 10
Study ECH protocol (RFC 9460) and TLS 1.3 internals

Build and run Apache from the ECH-enabled fork

Document build and configuration steps in LaTeX

Notes

Focus on a clean, reproducible build process

November 11 – 24
Compile OpenSSL with ECH support (Cloudflare branch)

Link Apache build to that OpenSSL

Verify ECH directives such as SSLECHKeyDir

Notes

Record logs, errors, and solutions for future reference

November 25 – December 8
Configure Apache for ECH with valid certificates

Test ECH handshake using openssl s_client and Wireshark

Document test outputs and success criteria

Notes

Achieve first working ECH connection

December 9 – 22
Develop automated local test scripts

Run interoperability tests with Firefox Nightly and Chrome Canary

Document success/failure results

Notes

Begin comparing browser behavior and TLS fingerprints

December 23 – January 5
Mid-project progress summary

Push builds, configurations, and notes to GitHub

Produce an interim LaTeX report (PDF)

Notes

Validate current work before automation stage

January 6 – 19
Build an automated test harness (Python + Selenium)

Collect logs for ECH success/failure cases

Notes

Ensure tests run headlessly and are repeatable

January 20 – February 2
Integrate test harness into CI (GitHub Actions or Jenkins)

Automate Apache build and testing pipeline

Notes

Emphasize reproducibility and automation

February 3 – 16
Run large-scale interoperability and fallback tests

Measure latency and CPU overhead with/without ECH

Notes

Gather quantitative data for final report graphs

February 17 – March 1
Write LaTeX report: methodology, results, and analysis

Include figures, charts, and structured data

Notes

Ensure report clarity and academic quality

March 2 – 15
Review feedback from supervisor

Clean and document repository (configs, scripts, reports)

Notes

Finalize documentation and naming conventions

March 16 – 29
Prepare presentation and demo

Test CI pipeline and live ECH-enabled Apache setup

Notes

Keep the demo simple, reliable, and reproducible

March 30 – April 12
Submit final report and all deliverables

Stretch Goal: Open a pull request contributing test harness/docs to Apache httpd

Present final project demo

Notes

Ensure repository, PDF, and presentation materials are complete
