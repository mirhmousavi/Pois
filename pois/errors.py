class PoisError(Exception):
    pass


class IDNAError(PoisError):
    pass


class TldsFileError(PoisError):
    pass


class BadDomainError(PoisError):
    pass


class NoWhoisServerFoundError(PoisError):
    pass


class SocketError(PoisError):
    pass


class SocketTimeoutError(SocketError):
    pass


class SocketBadProxyError(SocketError):
    pass
