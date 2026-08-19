import logging
from typing import Any, Literal

from requests import HTTPError, Response, request
from requests.exceptions import ConnectionError, Timeout

from app.logging.context import CORRELATION_ID_HEADER, UNSET, correlation_id_var

logger = logging.getLogger(__name__)


class HttpService:
    def __init__(
        self,
        endpoint: str,
        timeout: int,
        mtls_cert: str | None,
        mtls_key: str | None,
        verify_ca: str | bool,
    ):
        self._endpoint = endpoint
        self._timeout = timeout
        self._mtls_cert = mtls_cert
        self._mtls_key = mtls_key
        self._verify_ca = verify_ca

    def do_request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        sub_route: str = "",
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
        form_data: dict[str, Any] | None = None,
    ) -> Response:
        try:
            cert = (
                (self._mtls_cert, self._mtls_key)
                if self._mtls_cert and self._mtls_key
                else None
            )

            if data is not None and form_data is not None:
                raise ValueError(
                    "Cannot provide both 'data' and 'form_data' in the same request."
                )

            data_args = {}
            if form_data is not None:
                data_args["data"] = form_data
            elif data is not None:
                data_args["json"] = data

            outgoing_headers = dict(headers or {})
            correlation_id = correlation_id_var.get()
            if correlation_id != UNSET:
                outgoing_headers[CORRELATION_ID_HEADER] = correlation_id

            response = request(
                method=method,
                url=f"{self._endpoint}/{sub_route}" if sub_route else self._endpoint,
                params=params,
                headers=outgoing_headers,
                timeout=self._timeout,
                cert=cert,
                verify=self._verify_ca,
                **data_args,  # type: ignore
            )

            return response
        except (ConnectionError, Timeout):
            logger.exception("Request failed")
            raise
        except HTTPError:
            logger.exception("HTTP error occurred")
            raise
