"""Copy this file when starting a new module."""
from __future__ import annotations

from elevadr_modules.models import AnalysisContext, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


class ExampleModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="example",
        name="Example Module",
        description="Replace this description.",
        category="security_analysis",
        required_logs=("conn",),
        required_any_logs=(),
        default_enabled=False,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        # 1. Validate required logs if useful.
        # 2. Inspect normalized context data.
        # 3. Return standardized findings/metrics/evidence.
        return ModuleResult(module_id=self.metadata.id)
