from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Callable

from . import authorization, identity, registry
from .admission import (
    AdmissionStateError,
    ConcurrencyLimitExceeded,
    GatewayAdmissionController,
    RateLimitExceeded,
)
from .observability import GatewayMetrics
from .operation_guard import ConfirmationError


class GatewayError(RuntimeError):
    pass


class ConfirmationRequired(GatewayError):
    def __init__(self, challenge: dict):
        super().__init__("explicit confirmation required")
        self.challenge = challenge


@dataclass(frozen=True)
class InvocationContext:
    """Resolved identity context used only inside the gateway core."""

    principal_id: str
    source_provider: str
    source_subject: str
    request_id: str


class Gateway:
    def __init__(
        self,
        *,
        tools: dict,
        executors: dict,
        policy: dict,
        identity_resolver: Callable[[str, str], str],
        executor_call: Callable[[dict, dict], dict],
        audit_sink: Callable[[dict], None] | None = None,
        audit_failure_handler: Callable[[Exception, dict], None] | None = None,
        operation_guard=None,
        admission_controller=None,
        metrics: GatewayMetrics | None = None,
        max_catalog_combinations: int = 256,
    ):
        registry.validate_tool_registry(tools)
        registry.validate_executor_registry(executors)
        authorization.validate_policy(policy)
        if not callable(identity_resolver):
            raise TypeError("identity_resolver must be callable")
        if audit_failure_handler is not None and not callable(audit_failure_handler):
            raise TypeError("audit_failure_handler must be callable")
        if metrics is not None and not isinstance(metrics, GatewayMetrics):
            raise TypeError("metrics must be GatewayMetrics")
        if (
            isinstance(max_catalog_combinations, bool)
            or not isinstance(max_catalog_combinations, int)
            or max_catalog_combinations < 1
        ):
            raise ValueError("max_catalog_combinations must be a positive integer")
        self.tools = tools
        self.executors = executors
        self.policy = policy
        self.identity_resolver = identity_resolver
        self.executor_call = executor_call
        self.audit_sink = audit_sink
        self.audit_failure_handler = audit_failure_handler
        self.operation_guard = operation_guard
        self.metrics = metrics
        self.admission_controller = (
            GatewayAdmissionController()
            if admission_controller is None
            else admission_controller
        )
        self.max_catalog_combinations = max_catalog_combinations

    def _metric_event(self, event: str) -> None:
        if self.metrics is None:
            return
        try:
            self.metrics.record_event(event)
        except Exception:
            # Observability is intentionally best-effort and must never alter
            # authorization, confirmation or execution semantics.
            pass

    def _metric_begin(self, operation: str) -> float | None:
        if self.metrics is None:
            return None
        try:
            return self.metrics.begin_request(operation)
        except Exception:
            return None

    def _metric_finish(
        self,
        operation: str,
        outcome: str,
        started_at: float | None,
    ) -> None:
        if self.metrics is None or started_at is None:
            return
        try:
            self.metrics.finish_request(operation, outcome, started_at)
        except Exception:
            pass

    def _acquire_admission(self, source: identity.SourceContext):
        try:
            return self.admission_controller.acquire(source)
        except RateLimitExceeded:
            self._metric_event("admission_rate_limited")
            raise
        except ConcurrencyLimitExceeded:
            self._metric_event("admission_concurrency_limited")
            raise
        except AdmissionStateError:
            self._metric_event("admission_state_error")
            raise

    def _audit(
        self,
        event: str,
        source: identity.SourceContext,
        *,
        principal_id: str | None = None,
        best_effort: bool = False,
        **fields,
    ) -> None:
        if self.audit_sink is None:
            return
        record = {
            "event": event,
            "request_id": source.request_id,
            "source_provider": source.source_provider,
            "source_subject": source.source_subject,
            **fields,
        }
        if principal_id is not None:
            record["principal_id"] = principal_id
        try:
            self.audit_sink(record)
        except Exception as exc:
            self._metric_event(
                "audit_best_effort_failure"
                if best_effort
                else "audit_required_failure"
            )
            if not best_effort:
                raise
            if self.audit_failure_handler is not None:
                try:
                    self.audit_failure_handler(exc, record)
                except Exception:
                    pass

    @staticmethod
    def _validate_source(source: identity.SourceContext) -> None:
        if not isinstance(source, identity.SourceContext):
            raise GatewayError("source context must be created by the transport adapter")
        if not all(
            isinstance(value, str) and value
            for value in (
                source.source_provider,
                source.source_subject,
                source.request_id,
            )
        ):
            raise GatewayError("invalid source context")

    def _resolve_context(self, source: identity.SourceContext) -> InvocationContext:
        self._validate_source(source)
        try:
            principal = self.identity_resolver(
                source.source_provider,
                source.source_subject,
            )
        except identity.IdentityDenied:
            self._metric_event("identity_denied")
            self._audit("identity_denied", source, best_effort=True)
            raise
        if not isinstance(principal, str) or not principal:
            raise GatewayError("identity resolver returned an invalid principal")
        return InvocationContext(
            principal,
            source.source_provider,
            source.source_subject,
            source.request_id,
        )

    def _catalog_item(self, principal_id: str, name: str, item: dict) -> dict | None:
        tool = registry.get_tool(name, registry=self.tools)
        placeholders = registry.resource_argument_names(tool["resource"])
        if not placeholders:
            try:
                authorization.authorize(
                    principal_id,
                    tool["permission"],
                    tool["resource"],
                    tool["risk"],
                    policy=self.policy,
                )
            except authorization.AuthorizationDenied:
                return None
            return item

        enum_arguments: list[tuple[str, list]] = []
        combinations = 1
        for placeholder in placeholders:
            spec = tool.get("arguments", {}).get(placeholder, {})
            values = spec.get("enum")
            if not isinstance(values, list) or not values:
                return None
            combinations *= len(values)
            if combinations > self.max_catalog_combinations:
                return None
            enum_arguments.append((placeholder, values))

        allowed_combinations = []
        for values in itertools.product(
            *(values for _name, values in enum_arguments)
        ):
            args = dict(
                zip(
                    (name for name, _values in enum_arguments),
                    values,
                )
            )
            resource = tool["resource"].format(**args)
            try:
                authorization.authorize(
                    principal_id,
                    tool["permission"],
                    resource,
                    tool["risk"],
                    policy=self.policy,
                )
            except authorization.AuthorizationDenied:
                continue
            allowed_combinations.append(args)

        if not allowed_combinations:
            return None

        allowed_values_by_argument = {
            placeholder: [
                value
                for value in original_values
                if value
                in {
                    combo[placeholder]
                    for combo in allowed_combinations
                }
            ]
            for placeholder, original_values in enum_arguments
        }

        # The public catalog schema represents each enum independently. If
        # authorization permits only correlated combinations, independently
        # filtered enums would advertise unauthorized Cartesian-product pairs.
        # Hide the tool rather than publish a misleading capability surface.
        authorized_tuples = {
            tuple(combo[name] for name, _values in enum_arguments)
            for combo in allowed_combinations
        }
        advertised_tuples = set(
            itertools.product(
                *(
                    allowed_values_by_argument[name]
                    for name, _values in enum_arguments
                )
            )
        )
        if advertised_tuples != authorized_tuples:
            return None

        filtered = {
            **item,
            "arguments": {
                arg_name: dict(spec)
                for arg_name, spec in item["arguments"].items()
            },
        }
        for placeholder, _original_values in enum_arguments:
            filtered["arguments"][placeholder]["enum"] = (
                allowed_values_by_argument[placeholder]
            )
        return filtered

    def catalog(self, source: identity.SourceContext) -> list[dict]:
        started_at = self._metric_begin("catalog")
        outcome = "failed"
        lease = None
        try:
            self._validate_source(source)
            lease = self._acquire_admission(source)
            context = self._resolve_context(source)
            visible = []
            for item in registry.catalog(registry=self.tools):
                filtered = self._catalog_item(
                    context.principal_id,
                    item["name"],
                    item,
                )
                if filtered is not None:
                    visible.append(filtered)
            self._audit(
                "catalog_read",
                source,
                principal_id=context.principal_id,
                visible_tools=len(visible),
                best_effort=True,
            )
            outcome = "success"
            return visible
        except (RateLimitExceeded, ConcurrencyLimitExceeded):
            outcome = "admission_denied"
            raise
        except identity.IdentityDenied:
            outcome = "identity_denied"
            raise
        finally:
            if lease is not None:
                try:
                    self.admission_controller.release(lease)
                except Exception:
                    outcome = "failed"
                    raise
                finally:
                    self._metric_finish("catalog", outcome, started_at)
            else:
                self._metric_finish("catalog", outcome, started_at)

    def invoke(
        self,
        source: identity.SourceContext,
        tool_name: str,
        arguments: dict | None = None,
        *,
        confirmed: bool = False,
        confirmation_token: str | None = None,
    ) -> dict:
        started_at = self._metric_begin("invoke")
        outcome = "failed"
        lease = None
        try:
            self._validate_source(source)
            lease = self._acquire_admission(source)
            context = self._resolve_context(source)
            response = self._invoke_admitted(
                source,
                context,
                tool_name,
                arguments,
                confirmed=confirmed,
                confirmation_token=confirmation_token,
            )
            outcome = "success"
            return response
        except (RateLimitExceeded, ConcurrencyLimitExceeded):
            outcome = "admission_denied"
            raise
        except identity.IdentityDenied:
            outcome = "identity_denied"
            raise
        except authorization.AuthorizationDenied:
            outcome = "authorization_denied"
            raise
        except ConfirmationRequired:
            outcome = "confirmation_required"
            raise
        except ConfirmationError:
            outcome = "confirmation_denied"
            raise
        finally:
            if lease is not None:
                try:
                    self.admission_controller.release(lease)
                except Exception:
                    outcome = "failed"
                    raise
                finally:
                    self._metric_finish("invoke", outcome, started_at)
            else:
                self._metric_finish("invoke", outcome, started_at)

    def _invoke_admitted(
        self,
        source: identity.SourceContext,
        context: InvocationContext,
        tool_name: str,
        arguments: dict | None,
        *,
        confirmed: bool,
        confirmation_token: str | None,
    ) -> dict:
        tool = registry.materialize_tool(
            tool_name,
            arguments,
            registry=self.tools,
        )
        try:
            authorization.authorize(
                context.principal_id,
                tool["permission"],
                tool["resource"],
                tool["risk"],
                policy=self.policy,
            )
        except authorization.AuthorizationDenied:
            self._metric_event("authorization_denied")
            self._audit(
                "authorization_denied",
                source,
                principal_id=context.principal_id,
                tool=tool_name,
                resource=tool["resource"],
                risk=tool["risk"],
                best_effort=True,
            )
            raise

        route = registry.resolve_capability(
            tool["capability"],
            registry=self.executors,
        )

        explicit = tool.get("confirmation", "none") == "explicit"
        if explicit:
            if self.operation_guard is None:
                raise GatewayError("explicit confirmation guard is not configured")
            if not confirmed:
                challenge = self.operation_guard.issue(context, tool)
                self._metric_event("confirmation_required")
                self._audit(
                    "confirmation_required",
                    source,
                    principal_id=context.principal_id,
                    tool=tool_name,
                    resource=tool["resource"],
                    risk=tool["risk"],
                )
                raise ConfirmationRequired(challenge)
            if not confirmation_token:
                raise GatewayError("confirmation token is required")
            try:
                decision = self.operation_guard.begin(
                    confirmation_token,
                    context,
                    tool,
                )
            except ConfirmationError:
                self._metric_event("confirmation_denied")
                self._audit(
                    "confirmation_denied",
                    source,
                    principal_id=context.principal_id,
                    tool=tool_name,
                    resource=tool["resource"],
                    risk=tool["risk"],
                    best_effort=True,
                )
                raise
            if not decision["execute"]:
                self._metric_event("invoke_replayed")
                self._audit(
                    "invoke_replayed",
                    source,
                    principal_id=context.principal_id,
                    tool=tool_name,
                    resource=tool["resource"],
                    risk=tool["risk"],
                    best_effort=True,
                )
                return decision["response"]

        payload = {
            "schema": 1,
            "request_id": context.request_id,
            "principal_id": context.principal_id,
            "source": {
                "provider": context.source_provider,
                "subject": context.source_subject,
            },
            "capability": tool["capability"],
            "permission": tool["permission"],
            "risk": tool["risk"],
            "resource": tool["resource"],
            "request": tool["request"],
        }

        # This event is intentionally fail-closed: if durable audit is required
        # and cannot record the start, the external operation is not attempted.
        try:
            self._audit(
                "invoke_started",
                source,
                principal_id=context.principal_id,
                tool=tool_name,
                capability=tool["capability"],
                resource=tool["resource"],
                risk=tool["risk"],
                executor=route["executor_id"],
            )
        except Exception:
            if explicit:
                self.operation_guard.abort_before_execution(confirmation_token)
            raise

        try:
            response = self.executor_call(route, payload)
            if not isinstance(response, dict):
                raise GatewayError("executor returned an invalid response")
            if explicit:
                self.operation_guard.complete(
                    confirmation_token,
                    response,
                )
        except Exception as exc:
            self._metric_event("executor_failure")
            if explicit:
                self._metric_event("invoke_uncertain")
                try:
                    self.operation_guard.mark_uncertain(
                        confirmation_token
                    )
                finally:
                    self._audit(
                        "invoke_uncertain",
                        source,
                        principal_id=context.principal_id,
                        tool=tool_name,
                        resource=tool["resource"],
                        risk=tool["risk"],
                        error_type=type(exc).__name__,
                        best_effort=True,
                    )
            else:
                self._audit(
                    "invoke_failed",
                    source,
                    principal_id=context.principal_id,
                    tool=tool_name,
                    resource=tool["resource"],
                    risk=tool["risk"],
                    error_type=type(exc).__name__,
                    best_effort=True,
                )
            raise

        # Once the executor has succeeded, an audit backend outage must not
        # turn that success into a client-visible failure that encourages a
        # duplicate retry. The optional audit_failure_handler can surface the
        # degraded audit channel out-of-band.
        self._audit(
            "invoke_succeeded",
            source,
            principal_id=context.principal_id,
            tool=tool_name,
            resource=tool["resource"],
            risk=tool["risk"],
            best_effort=True,
        )
        return response
