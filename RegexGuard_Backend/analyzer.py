import re

class RegexAnalyzer:
    @staticmethod
    def detect_redos(pattern: str) -> dict:
        """Detects potential ReDoS vulnerabilities using static heuristics."""
        issues = []

        # Common catastrophic backtracking pattern: nested quantifiers
        if re.search(r'\([^\)]*[+*][^\)]*\)[+*]', pattern):
            issues.append("Possible nested quantifiers (catastrophic backtracking risk).")

        # Possessive quantifiers (not supported in Python, but check for them)
        if re.search(r'(\*\+|\+\+|\?\+|\{\d+,\}\+)', pattern):
            issues.append("Possessive quantifiers detected (may not be supported).")

        # Alternation with overlapping prefixes
        if re.search(r'(a|aa)+', pattern):
            issues.append("Overlapping alternations detected.")

        return {
            "vulnerable": bool(issues),
            "issues": issues
        }

    @staticmethod
    def static_analysis(pattern: str) -> dict:
        """Performs static analysis for common regex anti-patterns."""
        issues = []

        # Unanchored pattern check
        if not (pattern.startswith('^') or pattern.startswith(r'\A')):
            issues.append("Pattern is unanchored at start (^ or \\A missing).")
        if not (pattern.endswith('$') or pattern.endswith(r'\Z')):
            issues.append("Pattern is unanchored at end ($ or \\Z missing).")

        # Check for nested quantifiers
        if re.search(r'(\([^\)]*[+*][^\)]*\)[+*])', pattern):
            issues.append("Nested quantifiers detected.")

        # Check for overly broad wildcards
        if re.search(r'\.\*', pattern):
            issues.append("Greedy wildcard (.*) detected.")

        return {
            "issues": issues,
            "score": len(issues)
        }
