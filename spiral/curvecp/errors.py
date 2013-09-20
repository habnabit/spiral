class HandshakeTimeout(Exception):
    pass


class CurveCPConnectionDone(Exception):
    pass

class CurveCPConnectionFailed(CurveCPConnectionDone):
    pass


resolution_map = {
    'success': CurveCPConnectionDone,
    'failure': CurveCPConnectionFailed,
}
