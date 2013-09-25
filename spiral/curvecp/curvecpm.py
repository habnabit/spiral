import sys

from twisted.python import log


def addLogArguments(parser):
    parser.add_argument(
        '-Q', dest='verbosity', action='store_const', const='error', default='error')
    parser.add_argument(
        '-v', dest='verbosity', action='store_const', const='success')
    parser.add_argument(
        '-q', dest='verbosity', action='store_const', const='none')


def getLogObserver(verbosity):
    baseObserver = log.FileLogObserver(sys.stderr)

    if verbosity == 'none':
        return lambda ign: None
    elif verbosity == 'success':
        categories = {'success', 'error'}
    elif verbosity == 'error':
        categories = {'error'}
    else:
        raise ValueError('invalid verbosity', verbosity)

    def observer(event):
        if event['isError'] or event.get('category') in categories:
            baseObserver.emit(event)

    return observer


def startLogging(verbosity):
    log.defaultObserver.stop()
    log.addObserver(getLogObserver(verbosity))
