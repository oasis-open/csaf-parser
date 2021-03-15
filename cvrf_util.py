#!/usr/bin/env python
"""
Description:
Utility to parse and validate a CSAF Common Vulnerability Reporting Framework (CVRF)
file and display user-specified fields.

For additional information about CSAF or CVRF visit:
https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=csaf

Requirements:
* lxml (version 4.6.2)

This tool is based on the original cvrfparse utility created by Mike Schiffman of
Farsight Security under the MIT License. https://github.com/mschiffm/cvrfparse
"""

from __future__ import print_function

import os
import sys
import copy
# import codecs
# import urllib2
import argparse
import csv
from datetime import datetime
import logging
from lxml import etree

__revision__ = "1.2.0"


class CVRF_Syntax(object):
    # CVRF Elements and Namespaces.
    CVRF_ARGS = ["all", "DocumentTitle", "DocumentType", "DocumentPublisher", "DocumentTracking", "DocumentNotes",
                 "DocumentDistribution", "AggregateSeverity", "DocumentReferences", "Acknowledgments"]

    cvrf_versions = ["1.1", "1.2"]
    output_formats = ["csv", "html", "txt"]
    related_product_tags = ["all", "ProductID", "Status", "CVE", "Title", "BaseScore",
                            "Vector", "TemporalScore", "Note", "FullProductName",
                            "Branch", "Revision", "Remediation", "Acknowledgment", "Threat"]

    VULN_ARGS = ["all", "Title", "ID", "Notes", "DiscoveryDate", "ReleaseDate", "Involvements", "CVE", "CWE",
                 "ProductID",
                 "ProductStatuses", "Threats", "CVSSScoreSets", "Remediations", "References", "Acknowledgments",
                 "Vulnerability"]

    PROD_ARGS = ["all", "Branch", "FullProductName", "Relationship", "ProductGroups", "ProductID"]

    def __init__(self, cvrf_version):
        # defaults to current cvrf version 1.2 specification unless otherwise specified
        self.CVRF_SCHEMA = "http://docs.oasis-open.org/csaf/csaf-cvrf/v1.2/cs01/schemas/cvrf.xsd"
        self.NAMESPACES = {x.upper(): "{http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/%s}" % x for x in
                           ("cvrf", "vuln", "prod")}
        self.CVRF_CATALOG = "schemata/catalog_1_2.xml"
        self.CVRF_SCHEMA_FILE = "schemata/cvrf/1.2/cvrf.xsd"

        if cvrf_version == '1.1':
            self.CVRF_SCHEMA = "http://www.icasi.org/CVRF/schema/cvrf/1.1/cvrf.xsd"
            self.NAMESPACES = {x.upper(): "{http://www.icasi.org/CVRF/schema/%s/1.1}" % x for x in
                               ("cvrf", "vuln", "prod")}
            self.CVRF_CATALOG = "schemata/catalog_1_1.xml"
            self.CVRF_SCHEMA_FILE = "schemata/cvrf/1.1/cvrf.xsd"


class PrependerAction(argparse.Action):
    """
    Customization for argparse. Prepends some static text to an accumulated list.
    """
    prepend_text = ""

    def __call__(self, parser, namespace, values, option_string=None):
        orig = getattr(namespace, self.dest, None)
        items = [] if orig is None else copy.copy(orig)
        for value in values:
            items.append(self.prepend_text + value)
        setattr(namespace, self.dest, items)


class NonDupBracketFormatter(argparse.HelpFormatter):
    """
    Customization for argparse. A formatter that is a more terse in repeated arguments.
    """

    def _format_args(self, action, default_metavar):
        get_metavar = self._metavar_formatter(action, default_metavar)
        if action.nargs == argparse.ZERO_OR_MORE:
            result = "[%s ...]" % get_metavar(1)
        elif action.nargs == argparse.ONE_OR_MORE:
            result = "%s [...]" % get_metavar(1)
        else:
            result = super(NonDupBracketFormatter, self)._format_args(
                action, default_metavar)
        return result


# is node in the vuln namespace?
def is_vuln_ns(node, cvrf_version):
    tag = chop_ns_prefix(node.tag)
    ns = node.tag.replace(tag, '')

    if CVRF_Syntax(cvrf_version).NAMESPACES["VULN"] == ns:
        return True
    else:
        return False


def namespace_prepend(namespace, cvrf_version):
    """
    Returns a dynamic class (not instance) with appropriate prepend_text.
    """
    return type("Prepend_%s" % namespace, (PrependerAction,),
                {"prepend_text": CVRF_Syntax(cvrf_version).NAMESPACES[namespace]})


def chop_ns_prefix(element):
    """
    Return the element of a fully qualified namespace URI

    element: a fully qualified ET element tag
    """
    return element[element.rindex("}") + 1:]


def print_header_rows(cvrf_doc, cvrf_version, args, output_format, f=sys.stdout, related_product_tags=None):
    related_product_tags = [] if related_product_tags is None else related_product_tags
    column_names = list()
    column_names.append('Namespace')
    column_names.append('Tag')
    column_names.append('Text')
    column_names.append('Attributes')

    if args.include_related_product_elements:
        for tag in related_product_tags:
            column_names.append(tag)

    if output_format == 'html':

        now = datetime.now()
        html = '<b>File: ' + args.file + '</b><br>'
        html += '<span>Updated: ' + now.strftime("%m/%d/%Y %H:%M:%S") + '</span><br>'

        html += '<table border=1 cellpadding=3 cellspacing=3><tr bgcolor="#e9e9e9">'
        for column in column_names:
            if column in related_product_tags:
                html += '<th bgcolor="#a0a0a0">' + column + '</th>'
            else:
                html += '<th>' + column + '</th>'

        html += '</tr>'
        print(html, file=f)

    if output_format == 'csv':
        writer = csv.writer(f, dialect='excel')
        writer.writerow(column_names)


def print_footer_rows(cvrf_doc, cvrf_version, args, output_format, f=sys.stdout, related_product_tags=None):
    related_product_tags = [] if related_product_tags is None else related_product_tags
    if output_format == 'html':
        html = '</table>'
        print(html, file=f)


def print_node(cvrf_doc, cvrf_version, args, output_format, node, strip_ns, f=sys.stdout, related_product_tags=None):
    """
    Print each XML node

    node: the ElementTree node to be printed
    strip_ns: boolean that when true indicates the namespace prefix will be chomped
    f: the file to print to (default is stdout)
    """
    related_product_tags = [] if related_product_tags is None else related_product_tags
    related_values = {}

    # should we collect related product elements data?  (for vuln prod elements only)
    if is_vuln_ns(node, cvrf_version) and is_productid_node(node) and args.include_related_product_elements:
        vuln_root_node = get_vulnerability_node(node)
        related_values = get_related_vulnerability_values(vuln_root_node, related_values, node, cvrf_doc)

        product_node = get_product_name_node(cvrf_doc, cvrf_version, node.text.strip())
        related_values = get_related_producttree_values(product_node, related_values, node, cvrf_doc)

    if output_format == 'html':
        ns = tag = text = ''
        attribs = list()

        if node.tag:
            tag = chop_ns_prefix(node.tag)
            ns = node.tag.replace(tag, '')

        if node.text:
            text = node.text.strip()

        if node.attrib:
            for key in node.attrib:
                attribs.append("%s: %s" % (key, node.attrib[key]))

        html = '<tr>'
        html += '<td>' + ns + '</td>'
        html += '<td>' + tag + '</td>'
        html += '<td>' + text + '</td>'
        html += '<td>' + '\n'.join(attribs) + '</td>'

        # include optional related product elements
        if args.include_related_product_elements:
            for tag in related_product_tags:
                related_value = ''  # default value
                for k, v in related_values.items():
                    if k.startswith(tag):
                        related_value = v

                    if k.endswith(tag) and not k.startswith(tag):
                        if type(related_value) is not list:
                            related_value = list()
                        x = k.split('_')[0]
                        if type(v) is list:
                            related_value.append(x + ':' + '|'.join(v))
                        else:
                            related_value.append(x + ':' + v)

                related_value_txt = '<br>'.join(related_value) if type(related_value) is list else related_value
                html += '<td bgcolor="#ffffff">' + related_value_txt + '</td>'

        html += '</tr>'
        print(html, file=f)

    if output_format == 'txt':
        if node.tag:
            print("[%s]" % (chop_ns_prefix(node.tag) if strip_ns else node.tag), file=f)

        if node.text:
            print(node.text.strip(), file=f)

        if node.attrib:
            for key in node.attrib:
                print("(%s: %s)" % (key, node.attrib[key]), file=f)
            print('', file=f)

    if output_format == 'csv':
        writer = csv.writer(f, dialect='excel')

        ns = tag = text = ''
        attribs = list()

        if node.tag:
            tag = chop_ns_prefix(node.tag)
            ns = node.tag.replace(tag, '')

        if node.text:
            text = node.text.strip()

        if node.attrib:
            for key in node.attrib:
                attribs.append("%s: %s" % (key, node.attrib[key]))

        row_data = list()
        row_data.append(ns)
        row_data.append(tag)
        row_data.append(text)
        row_data.append('\n'.join(attribs))

        # include optional related product elements
        if args.include_related_product_elements:
            for tag in related_product_tags:
                related_value = ''
                for k, v in related_values.items():
                    if k.startswith(tag):
                        related_value = v

                    # combine values for similiar tag
                    if k.endswith(tag) and not k.startswith(tag):
                        if type(related_value) is not list:
                            related_value = list()
                        x = k.split('_')[0]
                        if type(v) is list:
                            related_value.append(x + ':' + '|'.join(v))
                        else:
                            related_value.append(x + ':' + v)

                related_value_txt = '\n'.join(related_value) if type(related_value) is list else related_value
                row_data.append(related_value_txt)

        writer.writerow(row_data)


def cvrf_validate(f, cvrf_doc):
    """
    Validates a CVRF document

    f: file object containing the schema
    cvrf_doc: the serialized CVRF ElementTree object
    returns: a code (True for valid / False for invalid) and a reason for the code
    """
    try:
        xmlschema_doc = etree.parse(f)
    except etree.XMLSyntaxError as e:
        log = e.error_log.filter_from_level(etree.ErrorLevels.FATAL)
        return False, "Parsing error, schema document \"{0}\" is not well-formed: {1}".format(f.name, log)
    xmlschema = etree.XMLSchema(xmlschema_doc)

    try:
        xmlschema.assertValid(cvrf_doc)
        return True, "Valid"
    except etree.DocumentInvalid:
        return False, xmlschema.error_log


def cvrf_dump(results, strip_ns, output_format, cvrf_doc, cvrf_version, args, related_product_tags):
    """
    Iterates over results and dumps to the dictionary key (which is a file handle)

    results: a dictionary of the format: {filename, [ElementTree node, ...], ...}
    strip_ns: boolean that when true indicates the namespace prefix will be chomped
    """
    for key in results:
        if key == output_format:  # if no file name specified, use stdout - "stdout"
            f = sys.stdout
        else:
            f = open(key, "w")

        print_header_rows(cvrf_doc, cvrf_version, args, output_format, f, related_product_tags)

        for item in results[key]:
            print_node(cvrf_doc, cvrf_version, args, output_format, item, strip_ns, f, related_product_tags)

        print_footer_rows(cvrf_doc, cvrf_version, args, output_format, f, related_product_tags)

        f.close()


def cvrf_dispatch(cvrf_doc, parsables, collate_vuln, strip_ns, cvrf_version, output_format, output_file, args,
                  related_product_tags):
    """
    Filter through a CVRF document and perform user-specified actions and report the results

    cvrf_doc: the serialized CVRF ElementTree object
    collate_vuln: boolean indicating whether or not to collate the vulnerabilities
    strip_ns: boolean that when true indicates the namespace prefix will be chomped
    returns: N/A
    """
    if parsables:
        results = cvrf_parse(cvrf_doc, parsables, output_format, output_file, args, cvrf_version)
        cvrf_dump(results, strip_ns, output_format, cvrf_doc, cvrf_version, args, related_product_tags)

    if collate_vuln:
        results = cvrf_collate_vuln(cvrf_doc, cvrf_version, output_format)
        cvrf_dump(results, strip_ns, output_format, cvrf_doc, cvrf_version, args, related_product_tags)


# get the parent Vulnerability node
def get_vulnerability_node(node):
    while node is not None:
        if chop_ns_prefix(node.tag) == 'Vulnerability':
            return node
        node = node.getparent()
    return node


# get the vulnerability ordinal value so we can use to group elements
def get_vulnerability_ordinal(node):
    ordinal = 0
    while node is not None:
        if chop_ns_prefix(node.tag) == 'Vulnerability':
            ordinal = node.attrib['Ordinal']
        node = node.getparent()
    return ordinal


def get_cvrfdoc_root_node(node):
    while node.getparent() is not None:
        node = node.getparent()
    return node


def has_child_product_node(node, current_node):
    # get the nodes children and check to see if it contains the node matching specific ProductID
    children = node.getchildren()
    for child in children:
        tag = chop_ns_prefix(child.tag)
        if tag == 'ProductID':
            if child.text.strip() == current_node.text.strip():
                return True
    return False


def is_productid_node(node):
    if node is not None:
        tag = chop_ns_prefix(node.tag)
        if tag == 'ProductID':
            return True
    return False


def has_child_product_nodes(node):
    # get the nodes children and check to see if it contains ProductID nodes
    children = node.getchildren()
    for child in children:
        tag = chop_ns_prefix(child.tag)
        if tag == 'ProductID':
            return True
    return False


# for specified node, get related producttree values for current and parent nodes
def get_related_producttree_values(node, values, current_product_node, cvrf_doc):
    if node is not None:

        # climb the xpath node tree to the top capturing all the node values
        while node.getparent() is not None:

            # add values for current node
            if node.tag and node.text and node.attrib:
                tag = chop_ns_prefix(node.tag)

                text = []
                for key in node.attrib:
                    text.append(key + ':' + node.attrib[key])

                if node.text:
                    if len(node.text.strip()) > 0:
                        text.append(node.text.strip())

                text = '|'.join(text)
                if text:
                    if tag in values:
                        if type(values[tag]) is list:
                            values[tag].append(text)
                        else:
                            values[tag] = [values[tag], text]
                    else:
                        values[tag] = text

            # climb the tree
            node = node.getparent()

    return values


def get_partial_key_in_dict(key, dict):
    for k, v in dict.items():
        if k.startswith(key):
            return k
    return None


# for specified node, get related vulnerability values for parent node values, sibling node values, etc
def get_related_vulnerability_values(node, values, current_product_node, cvrf_doc):
    if node is not None:
        children = node.getchildren()
        child_index = 0

        for child in children:
            child_index += 1

            # skip productid nodes
            if is_productid_node(child):
                continue

            # process the child if no children or has children specific properties for product
            process_child = False
            if len(child.getchildren()) == 0:  # element has no children, applies to all elements
                process_child = True

            if has_child_product_nodes(child):
                if has_child_product_node(child, current_product_node):
                    process_child = True  # has children and applies to desired product id
            else:
                process_child = True  # has children but not for specific product, applies to all elements

            if not process_child:
                continue

            if child.tag and child.attrib:
                tag = chop_ns_prefix(child.tag) + '_' + chop_ns_prefix(child.getparent().tag)

                text = []
                for key in child.attrib:
                    text.append(key + ':' + child.attrib[key])

                if child.text:
                    if len(child.text.strip()) > 0:
                        text.append(child.text.strip())

                text = '|'.join(text)
                if text:
                    if tag in values:
                        if type(values[tag]) is list:
                            values[tag].append(text)
                        else:
                            values[tag] = [values[tag], text]
                    else:
                        values[tag] = text

            if child.tag and child.text and not child.attrib:
                tag = chop_ns_prefix(child.tag) + '_' + chop_ns_prefix(child.getparent().tag)
                child_tag = chop_ns_prefix(child.tag)
                parent_tag = chop_ns_prefix(child.getparent().tag)
                text = child.text.strip()

                if text:
                    # put all elements with same parent tag together
                    parent_key = get_partial_key_in_dict(parent_tag, values)
                    if parent_key is not None:
                        if type(values[parent_key]) is not list:
                            values[parent_key] += '|' + child_tag + ':' + text
                        else:
                            values[parent_key][-1] += '|' + child_tag + ':' + text
                    else:
                        # convert to list when multiple elements exist for same tag
                        if tag in values:
                            if type(values[tag]) is list:
                                values[tag].append(text)
                            else:
                                values[tag] = [values[tag], text]
                        else:
                            values[tag] = text

            # recursively get the values for the child
            values = get_related_vulnerability_values(child, values, current_product_node, cvrf_doc)

        # include the current product id
        if current_product_node.tag and current_product_node.text:
            tag = chop_ns_prefix(current_product_node.tag)
            text = current_product_node.text.strip()
            values[tag] = text

    return values


def cvrf_parse(cvrf_doc, parsables, output_format, output_file, args, cvrf_version):
    """
    Parse a cvrf_doc and return a list of elements as determined by parsables

    cvrf_doc: the serialized CVRF ElementTree object
    parsables: list of elements to parse from a CVRF doc
    returns: a dictionary of the format {filename:[item, ...]}
    """
    items = []
    ordinal_products = {}

    for element in parsables:
        for node in cvrf_doc.iter(element):
            for child in node.iter():

                # process vuln productid elements uniquely by productid?
                if is_vuln_ns(child, cvrf_version):
                    if is_productid_node(child) and args.unique_products:
                        ordinal = get_vulnerability_ordinal(child)
                        if ordinal not in ordinal_products:
                            ordinal_products[ordinal] = []

                        product_id = child.text.strip() if child.text else ''
                        if product_id not in ordinal_products[ordinal]:
                            ordinal_products[ordinal].append(product_id)
                            items.append(child)
                    else:
                        # capture all non-productid elements
                        items.append(child)
                else:
                    # capture all non-vuln ns elements
                    items.append(child)

    # Hardcoded output for now, eventually make this user-tunable
    key = output_file if output_file else output_format
    return {key: items}  # "stdout"


def cvrf_collate_vuln(cvrf_doc, cvrf_version, output_format):
    """
    Zip through a cvrf_doc and return all vulnerability elements collated by ordinal

    cvrf_doc: the serialized CVRF ElementTree object
    returns: a dictionary of the format {filename:[item, ...], filename:[item, ...]}
    """
    results = {}
    # Obtain document title to use in the filename(s) tiptoeing around around the curly braces in our NS definition
    document_title = cvrf_doc.findtext("cvrf:DocumentTitle",
                                       namespaces={"cvrf": CVRF_Syntax(cvrf_version).NAMESPACES["CVRF"].replace("{",
                                                                                                                "").replace(
                                           "}", "")}).strip().replace(" ", "_")

    # Constrain Xpath search to the Vulnerability container
    for node in cvrf_doc.findall(".//" + CVRF_Syntax(cvrf_version).NAMESPACES["VULN"] + "Vulnerability"):
        # Create filename based on ordinal number to use as a key for results dictionary
        fileext = output_format if output_format else "txt"
        filename = "csaf-parser-" + document_title + "-ordinal-" + node.attrib["Ordinal"] + "." + fileext  # ".txt"

        filename = filename.replace(':', '')

        # Create an iterator to iterate over each child element and populate results dictionary values
        results[filename] = node.iter()

    return results


def get_product_name_node(cvrf_doc, cvrf_version, product_id):
    # Constrain Xpath search to the ProductTree container
    for node in cvrf_doc.findall(".//" + CVRF_Syntax(cvrf_version).NAMESPACES["PROD"] + "ProductTree"):
        for child in node.iter():
            if child.attrib and 'ProductID' in child.attrib:
                if child.attrib['ProductID'] == product_id:
                    return child
    return None


def process_related_product_tag_args(args, valid_related_product_tags):
    tags = []

    related_tags = args.related_product_tags
    if related_tags is not None:
        if "all" in related_tags:
            for tag in valid_related_product_tags:
                tags.append(tag)
            tags.remove("all")
        else:
            for tag in related_tags:
                tags.append(tag)

    return tags


def post_process_arglist(arg, namespace, valid_args, cvrf_version):
    parsables = []

    if CVRF_Syntax(cvrf_version).NAMESPACES[namespace] + "all" in arg:
        for element in valid_args:
            parsables.append(CVRF_Syntax(cvrf_version).NAMESPACES[namespace] + element)
        parsables.remove(CVRF_Syntax(cvrf_version).NAMESPACES[namespace] + "all")
    else:
        for element in arg:
            parsables.append(element)

    return parsables


# get the first parseable node in the cvrf document we are parsing
def get_first_node_in_doc(parsables, cvrf_doc):
    for element in parsables:
        for node in cvrf_doc.iter(element):
            for child in node.iter():
                return child
    return None


def derive_version_from_namespace(root):
    """Simplistic version detection of XML document from ETree object root."""
    not_found = ''
    versions = (
        'http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.1/cvrf',
        'http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf',
    )
    if root is None:
        return not_found

    mandatory_element = 'DocumentType'
    for version in versions:
        token = '{%s}%s' % (version, mandatory_element)
        if root.find(token) is not None:
            return version

    return not_found


def main(progname=None):
    # simple standard python logging
    logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename='csaf-parser.log',
                        level=logging.DEBUG)  # filemode='w',
    logging.info('-----------------------------------------------')

    progname = progname if progname else os.path.basename(sys.argv[0])
    logging.info(progname + ' v' + __revision__)
    logging.info('command line args: ' + str(sys.argv))

    default_cvrf_version = "1.2"
    default_output_format = "txt"  # ["csv", "html", "txt"]

    # get specified cvrf version from command line args if any present as its needed to process below args
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--cvrf-version")
    parser.add_argument("--cvrf")
    args, unknown = parser.parse_known_args()

    # get the cvrf fmt if specified, otherwise use the default
    cvrf_version = args.cvrf_version if args.cvrf_version else default_cvrf_version
    logging.info('cvrf_version: ' + cvrf_version)

    parser = argparse.ArgumentParser(formatter_class=NonDupBracketFormatter,
                                     description="Validate/parse a CVRF document and emit user-specified bits.")

    parser.add_argument("-f", "--file", required=True, action="store",
                        help="candidate CVRF XML file")

    parser.add_argument("--cvrf-version", action="store", default=cvrf_version,
                        choices=CVRF_Syntax(cvrf_version).cvrf_versions,
                        help="specify cvrf version")

    parser.add_argument("--output-file", action="store",
                        help="specify output file name")

    parser.add_argument("--output-format", action="store", default=default_output_format,
                        choices=CVRF_Syntax(cvrf_version).output_formats,
                        help="specify output format")

    parser.add_argument("--include-related-product-elements", dest="include_related_product_elements", default=False,
                        action="store_true",
                        help="specify if output should contains include related product elements.")

    parser.add_argument('--related-product-tags', nargs="*", choices=CVRF_Syntax(cvrf_version).related_product_tags,
                        action="store",
                        help="specify related product tags, use \"all\" to glob all related product elements.")

    parser.add_argument("--unique-products", dest="unique_products", default=False, action="store_true",
                        help="specify if output should contains unique product rows per vulnerability")

    parser.add_argument('--cvrf', nargs="*", choices=CVRF_Syntax(cvrf_version).CVRF_ARGS,
                        action=namespace_prepend("CVRF", cvrf_version),
                        help="emit CVRF elements, use \"all\" to glob all CVRF elements.")
    parser.add_argument("--vuln", nargs="*", choices=CVRF_Syntax(cvrf_version).VULN_ARGS,
                        action=namespace_prepend("VULN", cvrf_version),
                        help="emit Vulnerability elements, use \"all\" to glob all Vulnerability elements.")
    parser.add_argument("--prod", nargs="*", choices=CVRF_Syntax(cvrf_version).PROD_ARGS,
                        action=namespace_prepend("PROD", cvrf_version),
                        help="emit ProductTree elements, use \"all\" to glob all ProductTree elements.")

    parser.add_argument("-c", "--collate", dest="collate_vuln", default=False,
                        action="store_true",
                        help="collate all of the Vulnerability elements by ordinal into separate files")
    parser.add_argument("-s", "--strip-ns", dest="strip_ns", default=False, action="store_true",
                        help="strip namespace header from element tags before printing")
    parser.add_argument("-V", "--validate", default=False, action="store_true",
                        help="validate the CVRF document")

    parser.add_argument("-S", "--schema", action="store",
                        help="specify local alternative for cvrf.xsd")
    parser.add_argument("-C", "--catalog", action="store",
                        help="specify location for catalog.xml (default is {0})".format(
                            CVRF_Syntax(cvrf_version).CVRF_CATALOG))

    parser.add_argument("-v", "--version", action="version", version="%(prog)s " + __revision__)

    args = parser.parse_args()
    logging.info('command line args processed successfully')
    logging.info(args)

    logging.info('file to parse: ' + args.file)
    schema = args.schema if args.schema else CVRF_Syntax(cvrf_version).CVRF_SCHEMA_FILE
    logging.info('schema: ' + schema)

    catalog = args.catalog if args.catalog else CVRF_Syntax(cvrf_version).CVRF_CATALOG
    logging.info('catalog: ' + catalog)

    output_format = args.output_format if args.output_format else default_output_format
    logging.info('output format: ' + output_format)

    output_file = args.output_file if args.output_file else ''
    if output_file:
        logging.info('output file: ' + output_file)
    else:
        logging.info('output file not specified - using stdout')

    related_product_tags = process_related_product_tag_args(args, CVRF_Syntax(cvrf_version).related_product_tags)
    logging.info('related_product_tags: ' + ','.join(related_product_tags))

    # Post process argument lists into a single list, handling 'all' globs if present
    # this block should probably eventually be folded into argparse
    parsables = []
    if args.cvrf:
        parsables.extend(post_process_arglist(args.cvrf, "CVRF", CVRF_Syntax(cvrf_version).CVRF_ARGS, cvrf_version))
    if args.vuln:
        parsables.extend(post_process_arglist(args.vuln, "VULN", CVRF_Syntax(cvrf_version).VULN_ARGS, cvrf_version))
    if args.prod:
        parsables.extend(post_process_arglist(args.prod, "PROD", CVRF_Syntax(cvrf_version).PROD_ARGS, cvrf_version))

    logging.info('parse doc for below elements')
    logging.info('\n'.join(parsables))

    # First things first: parse the document (to ensure it is well-formed XML) to obtain an ElementTree object
    # to pass to the CVRF validator/parser
    try:
        logging.info('parsing document...')
        cvrf_doc = etree.parse(args.file, etree.XMLParser(encoding="utf-8"))  # "utf-8"
        logging.info('document successfully parsed')
    except IOError:
        logging.error("{0}: I/O error: \"{1}\" does not exist".format(progname, args.file))
        sys.exit("{0}: I/O error: \"{1}\" does not exist".format(progname, args.file))
    except etree.XMLSyntaxError as e:
        logging.error("{0}: Parsing error, document \"{1}\" is not well-formed: {2}".format(progname, args.file,
                                                                                            e.error_log.filter_from_level(
                                                                                                etree.ErrorLevels.FATAL)))
        sys.exit("{0}: Parsing error, document \"{1}\" is not well-formed: {2}".format(progname, args.file,
                                                                                       e.error_log.filter_from_level(
                                                                                           etree.ErrorLevels.FATAL)))

    # check to make sure cvrf namespace in doc matches cvrf version from command line args
    logging.info('verifying cvrf version...')
    doc_cvrf_version = derive_version_from_namespace(cvrf_doc.getroot())
    logging.info('cvrf version from document: %s' % doc_cvrf_version)
    arg_cvrf_version = CVRF_Syntax(cvrf_version).NAMESPACES["CVRF"].replace("{", "").replace("}", "")
    logging.info('cvrf version from args: ' + arg_cvrf_version)

    if doc_cvrf_version:
        if doc_cvrf_version == arg_cvrf_version:
            logging.info('OK: CVRF version matches document!')
        else:
            logging.error(
                'CVRF version mismatch! Specified cvrf version does not match the namespace in the cvrf document!')
            sys.exit(
                "{0}: CVRF version mismatch! Specified cvrf version does not match the namespace in the cvrf document!".format(
                    progname))
    else:
        logging.error(
            'Unable to check cvrf version in document. Cannot parse document or get node based on specified parseable elements!\nProbably a cvrf version mismatch...try using different cvrf version.')
        sys.exit(
            "{0}: Unable to check cvrf version in document. Cannot parse document or get node based on specified parseable elements!\nProbably a cvrf version mismatch...try using different cvrf version.".format(
                progname))

    if args.validate is True:
        logging.info('validating cvrf document...')

        try:
            if args.schema:
                # Try to use local schema files
                f = open(args.schema, 'r')

                # If the supplied file is not a valid catalog.xml or doesn't exist lxml will fall back to using remote validation
                catalog = args.catalog if args.catalog else CVRF_Syntax(cvrf_version).CVRF_CATALOG
                os.environ.update(XML_CATALOG_FILES=catalog)
            else:
                # try to use local schema file
                schema = CVRF_Syntax(cvrf_version).CVRF_SCHEMA_FILE
                f = open(schema, 'r')

                catalog = args.catalog if args.catalog else CVRF_Syntax(cvrf_version).CVRF_CATALOG
                os.environ.update(XML_CATALOG_FILES=catalog)

        except IOError as e:
            logging.error("{0}: I/O error({1}) \"{2}\": {3}".format(progname, e.errno, schema, e.strerror))
            sys.exit("{0}: I/O error({1}) \"{2}\": {3}".format(progname, e.errno, schema, e.strerror))

        (code, result) = cvrf_validate(f, cvrf_doc)
        f.close()

        if code is False:
            logging.error("{0}: {1}".format(progname, result))
            sys.exit("{0}: {1}".format(progname, result))
        else:
            logging.info(result)
            print(result, file=sys.stderr)

    logging.info('calling cvrf_dispatch...')
    cvrf_dispatch(cvrf_doc, parsables, args.collate_vuln, args.strip_ns, cvrf_version, output_format, output_file, args,
                  related_product_tags)
    logging.info('successfully finished...')


if __name__ == "__main__":
    progname = os.path.basename(sys.argv[0])

    try:
        main(progname)
    except Exception:
        (exc_type, exc_value, exc_tb) = sys.exc_info()
        sys.excepthook(exc_type, exc_value, exc_tb)  # if debugging
        sys.exit("%s: %s: %s" % (progname, exc_type.__name__, exc_value))

    logging.info('bye bye')
    sys.exit(0)
