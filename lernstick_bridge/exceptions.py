class KeylimeAPIError(BaseException):
    pass


class KeylimeRegistrarError(KeylimeAPIError):
    pass


class KeylimeAgentError(KeylimeAPIError):
    pass