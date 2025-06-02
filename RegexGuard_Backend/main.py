import re
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ValidationError , field_validator
from analyzer import RegexAnalyzer
from fuzzer import RegexFuzzer

app = FastAPI()

# Enable CORS (adjust origins for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class RegexRequest(BaseModel):
    pattern: str = Field(..., max_length=500)
    timeout: float = Field(1.0, ge=0.1, le=5.0)

    @field_validator('pattern')
    def validate_pattern(cls, v):
        if len(v) == 0:
            raise ValueError("Pattern must not be empty.")
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex: {str(e)}")
        return v

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}

@app.post("/analyze")
async def analyze_regex(request: RegexRequest):
    analyzer = RegexAnalyzer()
    fuzzer = RegexFuzzer()

    try:
        # Validate regex first
        re.compile(request.pattern)
    except re.error as e:
        raise HTTPException(400, detail=f"Invalid regex pattern: {str(e)}")

    redos_result = analyzer.detect_redos(request.pattern)
    static_issues = analyzer.static_analysis(request.pattern)
    
    # Pass timeout to fuzzer (critical fix)
    fuzz_results = fuzzer.fuzz_regex(
        pattern=request.pattern,
        timeout=request.timeout  # Now properly passed # type: ignore
    )

    return {
        "redos": redos_result,
        "static_analysis": static_issues,
        "fuzzing": fuzz_results
    }

@app.post("/convert/aws")
async def convert_to_aws_waf(request: RegexRequest):
    converted = request.pattern
    issues = []

    # AWS WAF limitations
    if re.search(r'\(\?<=[^)]*\)', converted) or re.search(r'\(\?<![^)]*\)', converted):
        issues.append("AWS WAF doesn't support lookbehind assertions.")
        converted = re.sub(r'\(\?<=[^)]*\)', '', converted)
        converted = re.sub(r'\(\?<![^)]*\)', '', converted)

    if re.search(r'\(\?P<[^>]+>', converted):
        issues.append("AWS WAF does not support named capture groups.")
        converted = re.sub(r'\(\?P<[^>]+>', '(', converted)

    if re.search(r'\\[1-9]', converted):
        issues.append("AWS WAF does not support backreferences.")

    return {
        "original": request.pattern,
        "converted": converted,
        "aws_rule": {
            "Name": "RegexGuard-Rule",
            "Priority": 1,
            "Statement": {
                "RegexMatchStatement": {
                    "FieldToMatch": {"UriPath": {}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    "RegexString": converted
                }
            }
        },
        "issues": issues,
        "aws_compatible": len(issues) == 0
    }
