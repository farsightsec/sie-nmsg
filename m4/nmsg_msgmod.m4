AC_DEFUN([MY_CHECK_LIBNMSG_MSGMOD],
    [AC_MSG_CHECKING([nmsg msgmod version])
    AC_RUN_IFELSE(
        [AC_LANG_PROGRAM(
            [[
            #include <nmsg/msgmod_plugin.h>
            ]],
            [[
            if (NMSG_MSGMOD_VERSION == 8)
                return (0);
            else
                return (1);
            ]]
        )]
        ,
        AC_MSG_RESULT([8])
        ,
        AC_MSG_FAILURE([nmsg msgmod version mismatch])
    )]
)
