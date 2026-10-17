"""Kuna API client that re-authenticates when the token is rejected.

pykuna 0.6.0 only treats a 403 as an expired token. The Kuna API now answers
401, which pykuna logs and swallows, so the token is never refreshed and every
request fails until Home Assistant restarts.
"""
import asyncio
import logging

from aiohttp import ClientResponseError
from pykuna import KunaAPI
from pykuna.kuna import API_URL, AUTH_ENDPOINT, USER_AGENT, USER_AGENT_THUMBNAIL

_LOGGER = logging.getLogger(__name__)

TOKEN_REJECTED_STATUSES = (401, 403)


class TokenRejected(Exception):
    """Raised when the Kuna API rejects the current token."""


class ReauthenticatingKunaAPI(KunaAPI):
    """KunaAPI that logs in again and retries once when its token is rejected.

    Cameras and recordings receive this object's bound _request, so every
    pykuna call goes through the retry.
    """

    def __init__(self, username, password, websession):
        super().__init__(username, password, websession)
        self._auth_lock = asyncio.Lock()

    async def _request(
        self, method, path, params=None, json=None, image=False, allow_redirects=True
    ):
        args = (method, path, params, json, image, allow_redirects)
        rejected_token = self._token
        try:
            return await self._send(*args)
        except TokenRejected:
            pass

        async with self._auth_lock:
            # Another request may already have refreshed the token.
            if self._token == rejected_token:
                _LOGGER.warning("Kuna API rejected the token; re-authenticating.")
                try:
                    await self.authenticate()
                except Exception as err:
                    _LOGGER.error("Kuna re-authentication failed: {}".format(err))
                    return None

        try:
            return await self._send(*args)
        except TokenRejected:
            _LOGGER.error("Kuna API rejected a freshly issued token: {}".format(path))
            return None

    async def _send(self, method, path, params, json, image, allow_redirects):
        """pykuna's KunaAPI._request, raising TokenRejected instead of swallowing it."""
        url = "{}/{}/".format(API_URL, path)
        headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}

        if self._token:
            headers["Authorization"] = "Token {}".format(self._token)

        if image or not allow_redirects:
            headers["User-Agent"] = USER_AGENT_THUMBNAIL

        try:
            async with self._websession.request(
                method,
                url,
                params=params,
                json=json,
                headers=headers,
                allow_redirects=allow_redirects,
            ) as result:
                result.raise_for_status()
                if image:
                    return await result.read()
                elif not allow_redirects:
                    return result
                else:
                    return await result.json()

        except ClientResponseError as err:
            # A rejected login is bad credentials, not a stale token.
            if err.status in TOKEN_REJECTED_STATUSES and path != AUTH_ENDPOINT:
                raise TokenRejected from err
            _LOGGER.error("Kuna API request error: {}".format(err))
            return None
