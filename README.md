<div>
<h1>README</h1>

<div>
<h2><a id="readme-general">OASIS TC Open Repository: csaf-parser</a></h2>

<p>This GitHub public repository ( <b><a href="https://github.com/oasis-open/csaf-parser">https://github.com/oasis-open/csaf-parser</a></b> ) was created at the request of the <a href="https://www.oasis-open.org/committees/csaf/">OASIS Common Security Advisory Framework (CSAF) TC</a> as an <a href="https://www.oasis-open.org/resources/open-repositories/">OASIS TC Open Repository</a> to support development of open source resources related to Technical Committee work.</p>

<p>While this TC Open Repository remains associated with the sponsor TC, its development priorities, leadership, intellectual property terms, participation rules, and other matters of governance are <a href="https://github.com/oasis-open/csaf-parser/blob/master/CONTRIBUTING.md#governance-distinct-from-oasis-tc-process">separate and distinct</a> from the OASIS TC Process and related policies.</p>

<p>All contributions made to this TC Open Repository are subject to open source license terms expressed in the <a href="https://www.oasis-open.org/sites/www.oasis-open.org/files/BSD-3-Clause.txt">BSD-3-Clause License</a>.  That license was selected as the declared <a href="https://www.oasis-open.org/resources/open-repositories/licenses">"Applicable License"</a> when the TC Open Repository was created.</p>

<p>As documented in <a href="https://github.com/oasis-open/csaf-parser/blob/master/CONTRIBUTING.md#public-participation-invited">"Public Participation Invited</a>", contributions to this OASIS TC Open Repository are invited from all parties, whether affiliated with OASIS or not.  Participants must have a GitHub account, but no fees or OASIS membership obligations are required.  Participation is expected to be consistent with the <a href="https://www.oasis-open.org/policies-guidelines/open-repositories">OASIS TC Open Repository Guidelines and Procedures</a>, the open source <a href="https://github.com/oasis-open/csaf-parser/blob/master/LICENSE">LICENSE</a> designated for this particular repository, and the requirement for an <a href="https://www.oasis-open.org/resources/open-repositories/cla/individual-cla">Individual Contributor License Agreement</a> that governs intellectual property.</p>

</div>

<div>
<h2><a id="purposeStatement">Statement of Purpose</a></h2>

<p>Statement of Purpose for this OASIS TC Open Repository (csaf-parser) as <a href="https://lists.oasis-open.org/archives/csaf/201711/msg00018.html">proposed</a> and <a href="https://www.oasis-open.org/committees/download.php/62129/csaf-minutes-20171129-meeting-12.html">approved</a> [<a href="https://issues.oasis-open.org/browse/TCADMIN-2812">bis</a>] by the TC:</p>

<p>The CSAF Parser (and validator) under development in this repository is a software tool for parsing and checking the syntax of the Common Vulnerability Reporting Framework (CVRF) machine readable security advisory content. The repository contains source code and associated documentation for the tool. The CSAF Parser can be used as a command-line tool or as a Python library which can be included in other applications.</p>

<p>[Earlier incarnations of the parser code included <a href="https://github.com/CiscoPSIRT/cvrf-util">cvrf-util</a> and Mike Schiffman's <a href="https://github.com/mschiffm/cvrfparse">cvrfparse</a>]</p>

<!--
https://www.cisco.com/c/en/us/about/security-center/missing-manual-cvrf-1-1.html
https://pypi.python.org/pypi/stix2-elevator/
https://pypi.python.org/pypi/medallion/
https://pypi.python.org/pypi/stix2/
https://pypi.python.org/pypi/taxii2-client/0.2.0
-->

</div>

<div>
<h1>CVRF Parsing Examples</h1>
<h2>Common use-case command-line examples</h2>
<p>One fairly common use-case would be to query a document and pull out the unique set of products with related fields from all vulnerabilities and save to excel file as shown below:

<span style="background-color: #e9e9e9">python cvrf_util.py --file examples/1.1/ms_cvrf.xml --schema schemata/cvrf/1.1/cvrf.xsd --cvrf-version 1.1 --output-format csv --output-file ms_cvrf.csv --vuln ProductID --include-related-product-elements --unique-products --related-product-tags all</span>
<br><br>

<table>
<tr><td colspan=2>Where the following command line parameters were applied:</td></tr>
<tr><td>--file examples/1.1/ms_cvrf.xml</td><td>Specify the document we are parsing</td></tr>
<tr><td>--schema schemata/cvrf/1.1/cvrf.xsd</td><td>Specify the schema</td></tr>
<tr><td>--cvrf-version 1.1</td><td>Specify the CVRF version</td></tr>
<tr><td>--output-format csv</td><td>Specify output format to CVS</td></tr>
<tr><td>--output-file ms_cvrf.csv</td><td>Specify the output file</td></tr>
<tr><td>--vuln ProductID</td><td>Specify elements to parse</td></tr>
<tr><td>--include-related-product-elements</td><td>Tell output to include related product elements</td></tr>
<tr><td>--unique-products</td><td>Specify that we want unique product rows per vulnerability</td></tr>
<tr><td>--related-product-tags all</td><td>Specify which related product element tags to include for each product row</td></tr>
</table>
</p>

<br>
<p>Another common example is to query a document and parse out all of the elements in each vulnerability and save to html file as shown below:</span>
<br><br>

<span style="background-color: #e9e9e9">python cvrf_util.py --file examples/1.1/ms_cvrf.xml --cvrf-version 1.1 --output-format html --output-file ms_cvrf.html --vuln Vulnerability --cvrf all --prod all</span>
<br><br>

<table>
<tr><td colspan=2>Where the following command line parameters were applied:</td></tr>
<tr><td>--file examples/1.1/ms_cvrf.xml</td><td>Specify the document we are parsing</td></tr>
<tr><td>--cvrf-version 1.1</td><td>Specify the CVRF version</td></tr>
<tr><td>--output-format html</td><td>Specify output format to HTML</td></tr>
<tr><td>--output-file ms_cvrf.html</td><td>Specify the output file</td></tr>
<tr><td>--vuln Vulnerability</td><td>Specify elements to parse</td></tr>
<tr><td>--cvrf all</td><td>Specify elements to parse</td></tr>
<tr><td>--prod all</td><td>Specify elements to parse</td></tr>
</table>


</div>

<div><h2><a id="purposeClarifications">Additions to Statement of Purpose</a></h2>

<p>Repository Maintainers may include here any clarifications &mdash; any additional sections, subsections, and paragraphs that the Maintainer(s) wish to add as descriptive text, reflecting (sub-) project status, milestones, releases, modifications to statement of purpose, etc.  The project Maintainers will create and maintain this content on behalf of the participants.</p>
</div>

<div>
<h2><a id="maintainers">Maintainers</a></h2>

<p>TC Open Repository <a href="https://www.oasis-open.org/resources/open-repositories/maintainers-guide">Maintainers</a> are responsible for oversight of this project's community development activities, including evaluation of GitHub <a href="https://github.com/oasis-open/csaf-parser/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-model">pull requests</a> and <a href="https://www.oasis-open.org/policies-guidelines/open-repositories#repositoryManagement">preserving</a> open source principles of openness and fairness. Maintainers are recognized and trusted experts who serve to implement community goals and consensus design preferences.</p>

<p>Initially, the associated TC members have designated one or more persons to serve as Maintainer(s); subsequently, participating community members may select additional or substitute Maintainers, per <a href="https://www.oasis-open.org/resources/open-repositories/maintainers-guide#additionalMaintainers">consensus agreements</a>.</p>

<p><b><a id="currentMaintainers">Current Maintainers of this TC Open Repository</a></b></p>

<ul>
<li><a href="mailto:os@cisco.com">Omar Santos</a>; GitHub ID: <a href="https://github.com/santosomar">santosomar</a>; WWW: <a href="http://www.cisco.com/">Cisco</a></li>

<li><a href="mailto:trfridle@cisco.com">Troy Fridley</a>; GitHub ID: <a href="https://github.com/trfridle">trfridle</a>; WWW: <a href="http://www.cisco.com/">Cisco</a></li>

</ul>

</div>

<div><h2><a id="aboutOpenRepos">About OASIS TC Open Repositories</a></h2>

<p><ul>
<li><a href="https://www.oasis-open.org/resources/open-repositories/">TC Open Repositories: Overview and Resources</a></li>
<li><a href="https://www.oasis-open.org/resources/open-repositories/faq">Frequently Asked Questions</a></li>
<li><a href="https://www.oasis-open.org/resources/open-repositories/licenses">Open Source Licenses</a></li>
<li><a href="https://www.oasis-open.org/resources/open-repositories/cla">Contributor License Agreements (CLAs)</a></li>
<li><a href="https://www.oasis-open.org/resources/open-repositories/maintainers-guide">Maintainers' Guidelines and Agreement</a></li>
</ul></p>

</div>

<div><h2><a id="feedback">Feedback</a></h2>

<p>Questions or comments about this TC Open Repository's activities should be composed as GitHub issues or comments. If use of an issue/comment is not possible or appropriate, questions may be directed by email to the Maintainer(s) <a href="#currentMaintainers">listed above</a>.  Please send general questions about TC Open Repository participation to OASIS Staff at <a href="mailto:repository-admin@oasis-open.org">repository-admin@oasis-open.org</a> and any specific CLA-related questions to <a href="mailto:repository-cla@oasis-open.org">repository-cla@oasis-open.org</a>.</p>

</div></div>
