__USER_SETUP__
__FS_READONLY_SETUP__
exec __EXEC_PREFIX__ \
    /usr/bin/env \
__ENV_STRIP_ARGS__
    HOME=__HOME__ \
    USER=__USER__ \
    LOGNAME=__LOGNAME__ \
    PATH=__PATH__ \
    /bin/bash.real -c __COMMAND_TO_RUN__
