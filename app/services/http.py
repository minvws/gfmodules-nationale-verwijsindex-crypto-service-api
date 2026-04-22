import logging
from typing import Any, Literal

from requests import HTTPError, Response, request
from requests.exceptions import ConnectionError, Timeout

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

            response = request(
                method=method,
                url=f"{self._endpoint}/{sub_route}" if sub_route else self._endpoint,
                params=params,
                headers=headers,
                timeout=self._timeout,
                cert=cert,
                verify=self._verify_ca,
                **data_args,  # type: ignore
            )

            return response
        except (ConnectionError, Timeout) as e:
            logger.error(f"Request failed: {e}")
            raise e
        except HTTPError as e:
            logger.error(f"HTTP error occurred: {e}")
            raise e
