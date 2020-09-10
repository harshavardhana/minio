import collections
import json
import os
import platform
import urllib.parse
from urllib.parse import urlsplit

import certifi
import minio.time as time
import urllib3
from minio.credentials import StaticProvider
from minio.error import MinioException
from minio.helpers import sha256_hash
from minio.signer import sign_v4_s3

__title__ = 'minioadm-py'
__author__ = 'MinIO, Inc.'
__version__ = '1.0.0'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2020 MinIO, Inc.'

_DEFAULT_USER_AGENT = "MinIO ({os}; {arch}) {lib}/{ver}".format(
    os=platform.system(), arch=platform.machine(),
    lib=__title__, ver=__version__,
)


def quote(resource, safe='/', encoding=None, errors=None):
    """
    Wrapper to urllib.parse.quote() replacing back to '~' for older python
    versions.
    """
    return urllib.parse.quote(
        resource,
        safe=safe,
        encoding=encoding,
        errors=errors,
    ).replace("%7E", "~")


def queryencode(query, safe='', encoding=None, errors=None):
    """Encode query parameter value."""
    return quote(query, safe, encoding, errors)


def get_scheme_host(url):
    """Gets scheme and host of an URL"""
    scheme = url.scheme
    host = url.netloc
    # Strip port 80/443 for HTTP/HTTPS.
    if (scheme == 'http' and url.port == 80) or (
            scheme == 'https' and url.port == 443):
        host = url.hostname

    return scheme, host


def get_target_url(endpoint_url, query=None):
    """
    Construct final target url.

    :param endpoint_url: Target endpoint url where request is served to.
    :param query: Query parameters as a *dict* for the target url.
    :return: Returns final target url as *str*.
    """

    # Parse url
    parsed_url = urllib.parse.urlsplit(endpoint_url)
    scheme, host = get_scheme_host(parsed_url)
    url_components = [scheme + '://' + host]
    url_components.append(parsed_url.path)

    if query:
        ordered_query = collections.OrderedDict(sorted(query.items()))
        query_components = []
        for component_key in ordered_query:
            if isinstance(ordered_query[component_key], list):
                for value in ordered_query[component_key]:
                    query_components.append(component_key + '=' +
                                            queryencode(value))
            else:
                query_components.append(
                    component_key + '=' +
                    queryencode(ordered_query.get(component_key, '')))

        query_string = '&'.join(query_components)
        if query_string:
            url_components.append('?')
            url_components.append(query_string)

    return ''.join(url_components)


class MinioAdm:  # pylint: disable=too-many-public-methods
    """
    MinIO admin client

    :param endpoint: Hostname of a MinIO service.
    :param access_key: Access key (aka user ID) of your account in
        MinIO service.
    :param secret_key: Secret Key (aka password) of your account in
        MinIO service.
    :param session_token: Session token of your account in MinIO service.
    :param secure: Flag to indicate to use secure (TLS) connection to MinIO
        service or not.
    :param http_client: Customized HTTP client.
    :param credentials: Credentials provider of your account in MinIO service.
    :return: :class:`MinioAdm <MinioAdm>` object

    Example::
        adm = MinioAdm('play.min.io',
                          access_key='Q3AM3UQ867SPQQA43P2F',
                          secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')
        adm.server_info()

    **NOTE on concurrent usage:** The `MinioAdm` object is thread safe when
    using the Python `threading` library. Specifically, it is **NOT** safe
    to share it between multiple processes, for example when using
    `multiprocessing.Pool`. The solution is simply to create a new `MinioAdm`
    object in each process, and not share it between processes.
    """

    # pylint: disable=too-many-function-args
    def __init__(self, endpoint,
                 access_key=None,
                 secret_key=None,
                 session_token=None,
                 api_version='v3',
                 secure=True,
                 http_client=None,
                 credentials=None):

        # Validate http client has correct base class.
        if http_client and not isinstance(
                http_client,
                urllib3.poolmanager.PoolManager):
            raise MinioException(
                'HTTP client should be of instance'
                ' `urllib3.poolmanager.PoolManager`'
            )

        # Default is a secured connection.
        scheme = 'https://' if secure else 'http://'
        self._api_version = 'v3'
        self._region_map = dict()
        self._endpoint_url = urlsplit(scheme + endpoint).geturl()
        self._is_ssl = secure
        self._user_agent = _DEFAULT_USER_AGENT
        if access_key:
            credentials = StaticProvider(access_key, secret_key, session_token)
        self._provider = credentials

        # Load CA certificates from SSL_CERT_FILE file if set
        ca_certs = os.environ.get('SSL_CERT_FILE') or certifi.where()
        self._http = http_client or urllib3.PoolManager(
            timeout=urllib3.Timeout.DEFAULT_TIMEOUT,
            maxsize=32,
            cert_reqs='CERT_REQUIRED',
            ca_certs=ca_certs,
            retries=urllib3.Retry(
                total=5,
                backoff_factor=0.2,
                status_forcelist=[500, 502, 503, 504]
            )
        )

    def _build_headers(self, host, headers, body, creds):
        """Build headers with given parameters."""
        headers = headers or {}
        headers["Host"] = host
        headers["User-Agent"] = self._user_agent

        if body:
            headers["Content-Length"] = str(len(body))
        if creds:
            headers["x-amz-content-sha256"] = sha256_hash('')

        date = time.utcnow()
        headers["x-amz-date"] = time.to_amz_date(date)
        return headers, date

    def _url_open(self, method, resource,
                  query=None,
                  body=None, headers=None,
                  content_sha256=None,
                  preload_content=True):
        """
        Open a url wrapper around signature version '4'
           and :meth:`urllib3.PoolManager.urlopen`
        """

        # Construct target url.
        creds = self._provider.retrieve() if self._provider else None

        url = get_target_url(self._endpoint_url+resource, query=query)
        urlobj = urllib.parse.urlsplit(url)

        headers, date = self._build_headers(urlobj.netloc, headers,
                                            body, creds)
        if creds:
            # Get signature headers if any.
            headers = sign_v4_s3(method,
                                 urlobj,
                                 '',
                                 headers,
                                 creds,
                                 headers.get("x-amz-content-sha256"),
                                 date)

        response = self._http.urlopen(method, url,
                                      body=body,
                                      headers=headers,
                                      preload_content=preload_content)

        if response.status not in [200, 204, 206]:
            # In case we did not preload_content, we need to release
            # the connection:
            if not preload_content:
                response.release_conn()

            if method in ['DELETE', 'GET', 'HEAD', 'POST', 'PUT']:
                raise ValueError(json.loads(response.data))

            raise ValueError('Unsupported method returned'
                             ' error: {0}'.format(response.status))

        return response

    def server_info(self):
        server_info_path = '/minio/admin/{0}/info'.format(self._api_version)
        resp = self._url_open('GET', server_info_path)
        return json.loads(resp.data)

    def data_usage(self):
        data_usage_path = '/minio/admin/{0}/datausageinfo'.format(
            self._api_version)
        resp = self._url_open('GET', data_usage_path)
        return json.loads(resp.data)


if __name__ == "__main__":
    adm = MinioAdm('play.min.io',
                   access_key='Q3AM3UQ867SPQQA43P2F',
                   secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')
    print(adm.data_usage())
