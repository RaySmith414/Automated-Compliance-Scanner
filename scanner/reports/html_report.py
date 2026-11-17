"""HTML report. The template is rendered with autoescaping on."""

from typing import Any, Dict, List, Tuple

from jinja2 import Environment, PackageLoader

from scanner.model import CATEGORIES, FRAMEWORK_KEYS


class HTMLReportGenerator:
    """Render scanner/reports/templates/report.html.

    Text collected from the scanned host (file names, host name, command
    output) is untrusted, so autoescape stays on for every value.
    """

    def __init__(self):
        self.environment = Environment(
            loader=PackageLoader("scanner.reports", "templates"),
            autoescape=True,
        )

    def render(self, result: Dict[str, Any]) -> str:
        grouped: List[Tuple[str, List[Dict[str, Any]]]] = []
        for category in CATEGORIES:
            checks = [c for c in result["checks"] if c["category"] == category]
            if checks:
                grouped.append((category, checks))
        template = self.environment.get_template("report.html")
        return template.render(
            result=result,
            summary=result["summary"],
            checks_by_category=grouped,
            framework_keys=FRAMEWORK_KEYS,
        )

    def generate(self, result: Dict[str, Any], output_path: str) -> None:
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(self.render(result))
