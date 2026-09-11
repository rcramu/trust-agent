from __future__ import annotations

from trustagent.gateway import TrustAgentGateway
from trustagent.models import AuthorizationRequest, Channel, Decision


class McpGateway:
    """MCP-shaped tool invocation: token + capability + resource."""

    def __init__(self, gateway: TrustAgentGateway) -> None:
        self.gateway = gateway

    def invoke(self, request: AuthorizationRequest) -> Decision:
        request.channel = Channel.MCP
        return self.gateway.authorize(request)


class A2AGateway:
    """A2A-shaped peer call: signed Agent Card + token."""

    def __init__(self, gateway: TrustAgentGateway) -> None:
        self.gateway = gateway

    def send(self, request: AuthorizationRequest) -> Decision:
        request.channel = Channel.A2A
        return self.gateway.authorize(request)
