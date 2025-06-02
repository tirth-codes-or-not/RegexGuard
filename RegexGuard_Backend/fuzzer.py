import json
import re
import time
from pathlib import Path
from hypothesis import strategies as st
from hypothesis import given, settings
from func_timeout import func_timeout, FunctionTimedOut

class RegexFuzzer:
    def __init__(self):
        self.payloads = self._load_attack_patterns()
        self.timeout = 2  # Seconds per test case
        
    def _load_attack_patterns(self) -> dict:
        """Load attack patterns with vulnerability metadata"""
        path = Path(__file__).parent / "payloads/attack_patterns.json"
        with open(path) as f:
            return json.load(f)
    
    @settings(max_examples=200, deadline=None)
    def fuzz_regex(self, pattern: str) -> dict:
        """Enhanced fuzzer with timeout protection and vulnerability classification"""
        results = {
            "bypasses": [],
            "reported_vulnerabilities": [],
            "tested_patterns": 0
        }
        
        try:
            compiled = re.compile(pattern)
        except re.error as e:
            return {"error": f"Invalid regex: {str(e)}"}
        
        # Test curated attack vectors
        for category, entries in self.payloads.items():
            for entry in entries:
                payload = entry["payload"]
                expected = entry.get("expected", "match")
                
                try:
                    match = func_timeout(
                        self.timeout,
                        compiled.search,
                        args=(payload,)
                    )
                except FunctionTimedOut:
                    results["reported_vulnerabilities"].append(
                        f"ReDoS detected with payload: {payload[:50]}..."
                    )
                    continue
                
                if (match and expected == "match") or (not match and expected == "nomatch"):
                    results["bypasses"].append({
                        "payload": payload,
                        "category": category,
                        "vulnerability": entry["type"]
                    })
        
        # Hypothesis-based fuzzing with targeted strategies
        @given(
            st.text(alphabet=st.characters(blacklist_categories=('Cc', 'Cs')), max_size=500),
            st.one_of(
                st.from_regex(pattern, fullmatch=True),
                st.just("a" * 1000),  # For repetition attacks
                st.just("\n" * 500)  # For line anchor bypass
            )
        )
        @settings(max_examples=100, deadline=None)
        def execute_fuzz(payload):
            results["tested_patterns"] += 1
            try:
                if func_timeout(self.timeout, compiled.search, args=(payload,)):
                    results["bypasses"].append({
                        "payload": payload[:500],  # Prevent huge payloads in reports
                        "category": "hypothesis_fuzz",
                        "vulnerability": "Unknown"
                    })
            except FunctionTimedOut:
                results["reported_vulnerabilities"].append(
                    f"ReDoS timeout triggered with generated payload"
                )
        
        execute_fuzz()
        
        # Post-process results
        results["vulnerable"] = len(results["bypasses"]) > 0 or len(results["reported_vulnerabilities"]) > 0
        return results
