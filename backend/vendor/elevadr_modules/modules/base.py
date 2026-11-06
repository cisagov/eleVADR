from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from elevadr_modules.models import AnalysisContext, ModuleResult


@dataclass(frozen=True, slots=True)
class ModuleMetadata:
    id: str
    name: str
    description: str
    category: str
    required_logs: tuple[str, ...]
    required_any_logs: tuple[str, ...] = ()
    default_enabled: bool = True


class AnalysisModule(ABC):
    metadata: ModuleMetadata

    def validate_context(self, context: AnalysisContext) -> list[str]:
        missing = [name for name in self.metadata.required_logs if not context.log(name)]
        if self.metadata.required_any_logs and not any(
            context.log(name) for name in self.metadata.required_any_logs
        ):
            missing.append("one of: " + ", ".join(self.metadata.required_any_logs))
        return missing

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> ModuleResult:
        raise NotImplementedError
