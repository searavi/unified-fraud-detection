"""
Auth Service

Real-user login against whichever IdP this deployment is configured for — Entra ID (Azure) or
AWS Cognito — so admin-gated Mesh actions (PUT /api/v1/hitl/policies/{tenantId}) work with a
real, tenant-issued token instead of Mesh's dev-only /local/token shortcut, which is
Production-disabled on both cloud Mesh deployments.

Provider is selected by which env vars are present, never a separate flag: AZURE_CLIENT_ID set
-> Entra (msal-python's ConfidentialClientApplication, mirroring Web/server/routes.ts's exact
pattern — confirmed portable, no Node-specific machinery). COGNITO_USER_POOL_ID set -> Cognito
hosted-UI OAuth2 authorization-code flow (plain httpx — Cognito's hosted UI is a standard OIDC
endpoint, no SDK needed for the token exchange itself). Neither set -> auth disabled (local dev;
investigation_service.py falls back to /local/token unchanged).

The resulting token is presented to Mesh UNMODIFIED (Authorization: Bearer <token>) — no
Mesh-side token exchange, matching Web's own proxyMeshAdminRequest pattern exactly.
"""

import logging
import os
from typing import Optional
from urllib.parse import urlencode

import httpx

try:
    import msal
except ImportError:
    msal = None

logger = logging.getLogger('investigation.auth')


class AuthService:
    def __init__(self):
        self.provider = self._detect_provider()

        self._entra_tenant_id = os.environ.get("AZURE_TENANT_ID", "")
        self._entra_client_id = os.environ.get("AZURE_CLIENT_ID", "")
        self._entra_client_secret = os.environ.get("AZURE_CLIENT_SECRET", "")

        self._cognito_domain = os.environ.get("COGNITO_DOMAIN", "")
        self._cognito_region = os.environ.get("AWS_REGION", "")
        self._cognito_client_id = os.environ.get("COGNITO_CLIENT_ID", "")
        self._cognito_client_secret = os.environ.get("COGNITO_CLIENT_SECRET", "")

        self._redirect_uri = os.environ.get("OAUTH_REDIRECT_URI", "")

        self._msal_app = None
        if self.provider == "entra":
            if msal is None:
                raise RuntimeError("AZURE_CLIENT_ID is set but the 'msal' package is not installed")
            self._msal_app = msal.ConfidentialClientApplication(
                client_id=self._entra_client_id,
                client_credential=self._entra_client_secret,
                authority=f"https://login.microsoftonline.com/{self._entra_tenant_id}",
            )

        logger.info(f"AuthService initialized — provider: {self.provider}")

    @staticmethod
    def _detect_provider() -> str:
        if os.environ.get("AZURE_CLIENT_ID"):
            return "entra"
        if os.environ.get("COGNITO_USER_POOL_ID"):
            return "cognito"
        return "none"

    @property
    def enabled(self) -> bool:
        return self.provider != "none"

    def build_login_redirect(self, state: str) -> str:
        """Returns the URL to redirect the browser to for login. Raises if no IdP is configured
        — callers should check .enabled first and skip offering a login option entirely.
        """
        if self.provider == "entra":
            return self._msal_app.get_authorization_request_url(
                scopes=["openid", "profile", "email"],
                redirect_uri=self._redirect_uri,
                state=state,
            )

        if self.provider == "cognito":
            params = {
                "response_type": "code",
                "client_id": self._cognito_client_id,
                "redirect_uri": self._redirect_uri,
                "scope": "openid profile email",
                "state": state,
            }
            return (
                f"https://{self._cognito_domain}.auth.{self._cognito_region}.amazoncognito.com"
                f"/oauth2/authorize?{urlencode(params)}"
            )

        raise RuntimeError("No IdP configured (neither AZURE_CLIENT_ID nor COGNITO_USER_POOL_ID is set)")

    async def handle_callback(self, code: str) -> str:
        """Exchanges an authorization code for a token, returned as-is for presentation to Mesh."""
        if self.provider == "entra":
            result = self._msal_app.acquire_token_by_authorization_code(
                code, scopes=["openid", "profile", "email"], redirect_uri=self._redirect_uri
            )
            if "access_token" not in result:
                raise RuntimeError(f"Entra token exchange failed: {result.get('error_description', result)}")
            return result["access_token"]

        if self.provider == "cognito":
            token_url = f"https://{self._cognito_domain}.auth.{self._cognito_region}.amazoncognito.com/oauth2/token"
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    token_url,
                    data={
                        "grant_type": "authorization_code",
                        "client_id": self._cognito_client_id,
                        "code": code,
                        "redirect_uri": self._redirect_uri,
                    },
                    auth=(self._cognito_client_id, self._cognito_client_secret),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            response.raise_for_status()
            token_data = response.json()
            # The ID token, not the access token: Mesh's AdminRoleAuthorizationHandler fallback
            # (HasConfiguredAdminClaim) reads cognito:groups off whatever's presented as the
            # Bearer token, and Cognito only puts cognito:groups on the ID token by default.
            return token_data["id_token"]

        raise RuntimeError("No IdP configured")


auth_service = AuthService()
