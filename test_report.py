import os
import textwrap
import json
from collections import OrderedDict

testcase_results = "Test Results: "
width = 80
score_separator = "/"
score_padding = " "
score_headings = OrderedDict()
score_headings["OK"] = "+"
score_headings["FAIL"] = "-"
score_headings["NOT TESTED"] = "O"
score_headings["_totals"] = "#"
score_heading_fragment = ""
stats_padding = 10
level_indention = [
    "",
    " .. ",
    "    > "
]
lengths = {
    "OK": 0,
    "FAIL": 0,
    "NOT TESTED": 0,
    "_totals": 0
}

# we also need all status texts to build a max
def read_file(uri):
    with open(uri, 'r') as file:
        return file.read()

def load_reports_from_prefix(prefix):
    return read_file( prefix + 'reports' ).strip().split("\n")

def format_report(report_files=None,prefix=None):
    output = []
    if bool(report_files) == bool(prefix):
        return None

    if prefix:
        report_files = load_reports_from_prefix(prefix)

    reports = {}
    for report_file in report_files:
        report = json.loads(read_file(report_file))
        reports[report["function"]] = report

    summary = generate_summary(reports)

    for test_func in summary:
        output.append(line_heading(summary[test_func]))
        output.append(line_dash(summary[test_func]))
        output.append(line_result(summary[test_func]))
        for sub_id in summary[test_func]["subs"]:
            output.append(line_result(summary[test_func]["subs"][sub_id]))
            for sub_sub_id in summary[test_func]["subs"][sub_id]["subs"]:
                output.append(line_status(summary[test_func]["subs"][sub_id]["subs"][sub_sub_id]))
            output.append(line_empty(summary[test_func]))


        output.append(line_dash(summary[test_func]))
        output.append(line_status(summary[test_func], testcase_results))
        output.append(line_empty(summary[test_func]))
    return output

def generate_summary(reports):
    global score_heading_fragment

    summary = OrderedDict()

    for heading in score_headings:
        lengths[heading] = len(score_headings[heading])

    # every testcase has x scenarios. every scenario has x assertions
    # the result should look the same (?)
    for test_case in reports:
        if len(str(len(reports[test_case]["tests"]))) > lengths["_totals"]:
            lengths["_totals"] = len(str(len(reports[test_case]["tests"])))

        for status in reports[test_case]["scores"]:
            if len(str(reports[test_case]["scores"][status])) > lengths[status]:
                lengths[status] = len(str(reports[test_case]["scores"][status]))

        for scenario_id in reports[test_case]["tests"]:
            scenario = reports[test_case]["tests"][scenario_id]

            if len(str(len(scenario["assertions"]))) > lengths["_totals"]:
                lengths["_totals"] = len(str(len(scenario["assertions"])))

            for status in scenario["scores"]:
                if len(str(scenario["scores"][status])) > lengths[status]:
                    lengths[status] = len(str(scenario["scores"][status]))

    score_heading_fragments = []
    for status in score_headings:
        score_heading_fragments += [
            '{heading:>{size}}'.format(
                heading=score_headings[status],
                size=lengths[status]
            )
        ]

    score_heading_fragment = (score_separator + score_padding).join(score_heading_fragments)
    lengths['score_heading_fragment'] = len(score_heading_fragment)

    for test_case in reports:
        status_fragments = []
        for status in score_headings:
            score = len(reports[test_case]["tests"])
            if status in reports[test_case]["scores"]:
                score = reports[test_case]["scores"][status]

            status_fragments += [
                '{score:>{size}}'.format(
                    score=score,
                    size=lengths[status]
                )
            ]
            status_fragment = (score_separator + score_padding).join(status_fragments)

        summary[test_case] = OrderedDict()
        summary[test_case]["text"] = reports[test_case]["desc"]
        summary[test_case]["score"] = status_fragment
        summary[test_case]["level"] = 0
        summary[test_case]["status"] = reports[test_case]["status"]
        summary[test_case]["subs"] = OrderedDict()

        for scenario_id in reports[test_case]["tests"]:
            status_fragments = []
            for status in score_headings:
                score = len(reports[test_case]["tests"][scenario_id]["assertions"])
                if status in reports[test_case]["tests"][scenario_id]["scores"]:
                    score = reports[test_case]["tests"][scenario_id]["scores"][status]

                status_fragments += [
                    '{score:>{size}}'.format(
                        score=score,
                        size=lengths[status]
                    )
                ]
                status_fragment = (score_separator + score_padding).join(status_fragments)

            summary[test_case]["subs"][scenario_id] = OrderedDict()
            summary[test_case]["subs"][scenario_id]["text"] = reports[test_case]["tests"][scenario_id]["test"]
            summary[test_case]["subs"][scenario_id]["score"] = status_fragment
            summary[test_case]["subs"][scenario_id]["level"] = 1
            summary[test_case]["subs"][scenario_id]["status"] = reports[test_case]["tests"][scenario_id]["status"]
            summary[test_case]["subs"][scenario_id]["subs"] = OrderedDict()

            for assertion_id in reports[test_case]["tests"][scenario_id]["assertions"]:
                assertion = reports[test_case]["tests"][scenario_id]["assertions"][assertion_id]
                summary[test_case]["subs"][scenario_id]["subs"][assertion_id] = {
                    "text": assertion["assertion"],
                    "status": assertion["status"],
                    "level": 2,
                    "score": "",
                    "subs": {}
                }

    return summary

def line_heading(node):
    return "{fill:{padding}}{heading:>{size}}".format(
        fill=" ",
        padding=(width - lengths["score_heading_fragment"]),
        heading=score_heading_fragment,
        size=lengths["score_heading_fragment"]
    )

def line_dash(node):
    return '-' * width

def line_status(node,text_override=None):
    available_width = ( width - stats_padding - lengths["score_heading_fragment"] - len(level_indention[node["level"]]) )

    align = "<"
    padding = " " * stats_padding
    text = node["text"]
    if text_override:
        available_width += stats_padding
        align = ">"
        text = text_override
        padding = ""

    lines = textwrap.wrap(
        text,
        available_width
    )

    if not text_override:
        lines = [
            level_indention[node["level"]] + line for line in lines
        ]

    lines[0] = "{text:{align}{size}}{status}".format(
        text=lines[0],
        align=align,
        size=(width - lengths["score_heading_fragment"]),
        padding=padding,
        status=node["status"]
    )
    return "\n".join(lines)


def line_empty(node):
    return ""

def line_result(node):
    available_width = ( width - stats_padding - lengths["score_heading_fragment"] - len(level_indention[node["level"]]) )

    lines = textwrap.wrap(
        node["text"],
        available_width
    )

    lines = [
        level_indention[node["level"]] + line for line in lines
    ]

    lines[0] = "{text}{score:>{size}}".format(
        text=lines[0],
        score=node["score"],
        size=(width - len(lines[0]))
    )
    return "\n".join(lines)
