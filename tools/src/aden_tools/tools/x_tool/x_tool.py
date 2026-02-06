"""
X (Twitter) Tool - Post tweets, reply, search, and read mentions via X API v2.

Supports:
- Bearer tokens (X_BEARER_TOKEN) for search and mentions
- OAuth2 tokens via credential store for DM, post, reply and delete operations

API Reference: https://developer.x.com/en/docs/twitter-api
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
import urllib.parse
import uuid
from typing import TYPE_CHECKING, Any

import httpx
from fastmcp import FastMCP

if TYPE_CHECKING:
    from aden_tools.credentials import CredentialStoreAdapter


X_API_BASE = "https://api.x.com/2"


# Clients


class _XBearerClient:
    """Internal client for read-only X API calls using Bearer token auth."""

    def __init__(self, bearer_token: str):
        self._bearer_token = bearer_token

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._bearer_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code == 401:
            return {"error": "Invalid or expired X Bearer token"}
        if response.status_code == 403:
            return {
                "error": "Insufficient permissions for this operation.",
                "help": "This endpoint may require OAuth user context.",
            }
        if response.status_code == 404:
            return {"error": "Resource not found"}
        if response.status_code == 429:
            return {"error": "Rate limit exceeded. Try again later."}
        if response.status_code >= 400:
            try:
                detail = response.json()
            except Exception:
                detail = response.text
            return {"error": f"X API error (HTTP {response.status_code}): {detail}"}
        return response.json()

    def get(self, endpoint: str, params: dict | None = None) -> dict[str, Any]:
        response = httpx.get(
            f"{X_API_BASE}{endpoint}",
            headers=self._headers,
            params=params,
            timeout=30.0,
        )
        return self._handle_response(response)


class _XOAuthClient:
    """Internal client for write operations using OAuth user context (X OAuth 1.0a)."""

    def __init__(
        self,
        api_key: str,
        api_secret: str,
        access_token: str,
        access_token_secret: str,
    ):
        self._api_key = api_key
        self._api_secret = api_secret
        self._access_token = access_token
        self._access_token_secret = access_token_secret

    def _generate_signature(
        self,
        method: str,
        url: str,
        oauth_params: dict[str, str],
        body_params: dict[str, str] | None = None,
    ) -> str:
        all_params = {**oauth_params}
        if body_params:
            all_params.update(body_params)

        sorted_params = sorted(all_params.items())
        param_string = "&".join(
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(str(v), safe='')}"
            for k, v in sorted_params
        )

        base_string = (
            f"{method.upper()}&"
            f"{urllib.parse.quote(url, safe='')}&"
            f"{urllib.parse.quote(param_string, safe='')}"
        )

        signing_key = (
            f"{urllib.parse.quote(self._api_secret, safe='')}&"
            f"{urllib.parse.quote(self._access_token_secret, safe='')}"
        )

        import base64

        return base64.b64encode(
            hmac.new(
                signing_key.encode("utf-8"),
                base_string.encode("utf-8"),
                hashlib.sha1,
            ).digest()
        ).decode("utf-8")

    def _auth_header(self, method: str, url: str) -> str:
        oauth_params = {
            "oauth_consumer_key": self._api_key,
            "oauth_nonce": uuid.uuid4().hex,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_token": self._access_token,
            "oauth_version": "1.0",
        }

        oauth_params["oauth_signature"] = self._generate_signature(method, url, oauth_params)

        parts = [
            f'{urllib.parse.quote(k, safe="")}="{urllib.parse.quote(v, safe="")}"'
            for k, v in sorted(oauth_params.items())
        ]
        return "OAuth " + ", ".join(parts)

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code == 401:
            return {"error": "OAuth authentication failed"}
        if response.status_code == 403:
            return {"error": "OAuth credentials lack required permissions"}
        if response.status_code == 404:
            return {"error": "Resource not found"}
        if response.status_code == 429:
            return {"error": "Rate limit exceeded"}
        if response.status_code >= 400:
            try:
                detail = response.json()
            except Exception:
                detail = response.text
            return {"error": f"X API error (HTTP {response.status_code}): {detail}"}
        return response.json()

    def post(self, endpoint: str, json_body: dict | None = None) -> dict[str, Any]:
        url = f"{X_API_BASE}{endpoint}"
        headers = {
            "Authorization": self._auth_header("POST", url),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        response = httpx.post(url, headers=headers, json=json_body, timeout=30.0)
        return self._handle_response(response)

    def delete(self, endpoint: str) -> dict[str, Any]:
        url = f"{X_API_BASE}{endpoint}"
        headers = {
            "Authorization": self._auth_header("DELETE", url),
            "Accept": "application/json",
        }
        response = httpx.delete(url, headers=headers, timeout=30.0)
        return self._handle_response(response)

# Tool registration

def register_tools(
    mcp: FastMCP,
    credentials: CredentialStoreAdapter | None = None,
) -> None:
    """Register X (Twitter) tools with the MCP server."""

    def _get_cred(env: str, name: str) -> str | None:
        if credentials is not None:
            val = credentials.get(name)
            if val is not None and not isinstance(val, str):
                raise TypeError(f"Expected string for credential '{name}'")
            return val
        return os.getenv(env)

    def _bearer_client():
        token = _get_cred("X_BEARER_TOKEN", "x_bearer_token")
        if not token:
            return {"error": "X Bearer token not configured"}
        return _XBearerClient(token)

    def _oauth_client():
        api_key = _get_cred("X_API_KEY", "x_api_key")
        api_secret = _get_cred("X_API_SECRET", "x_api_secret")
        access_token = _get_cred("X_ACCESS_TOKEN", "x_access_token")
        access_secret = _get_cred("X_ACCESS_TOKEN_SECRET", "x_access_token_secret")

        if not all([api_key, api_secret, access_token, access_secret]):
            return {
                "error": "OAuth credentials not configured",
                "help": "Post/reply/delete/DM require OAuth user context.",
            }
        return _XOAuthClient(api_key, api_secret, access_token, access_secret)



    @mcp.tool()
    def x_search_tweets(query: str, max_results: int = 10) -> dict:
        """
        Search recent tweets.

        oauth_required: False
        """
        client = _bearer_client()
        if isinstance(client, dict):
            return client
        return client.get(
            "/tweets/search/recent",
            {"query": query, "max_results": min(max_results, 100)},
        )

    @mcp.tool()
    def x_get_mentions(user_id: str, max_results: int = 10) -> dict:
        """
        Fetch recent mentions for a user.

        oauth_required: False
        """
        client = _bearer_client()
        if isinstance(client, dict):
            return client
        return client.get(
            f"/users/{user_id}/mentions",
            {"max_results": min(max_results, 100)},
        )

    

    @mcp.tool()
    def x_post_tweet(text: str) -> dict:
        """
        Post a new tweet.

        oauth_required: True
        """
        client = _oauth_client()
        if isinstance(client, dict):
            return client
        return client.post("/tweets", {"text": text})

    @mcp.tool()
    def x_reply_tweet(tweet_id: str, text: str) -> dict:
        """
        Reply to a tweet.

        oauth_required: True
        """
        client = _oauth_client()
        if isinstance(client, dict):
            return client
        return client.post(
            "/tweets",
            {"text": text, "reply": {"in_reply_to_tweet_id": tweet_id}},
        )

    @mcp.tool()
    def x_delete_tweet(tweet_id: str) -> dict:
        """
        Delete a tweet.

        oauth_required: True
        """
        client = _oauth_client()
        if isinstance(client, dict):
            return client
        return client.delete(f"/tweets/{tweet_id}")

    @mcp.tool()
    def x_send_dm(participant_id: str, text: str) -> dict:
        """
        Send a direct message to a user.

        oauth_required: True
        """
        client = _oauth_client()
        if isinstance(client, dict):
            return client
        return client.post(
            f"/dm_conversations/with/{participant_id}/messages",
            {"text": text},
        )
