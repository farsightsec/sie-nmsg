AC_DEFUN([MY_CHECK_LIBNMSG_MSGMOD],
    [AC_MSG_CHECKING([for matching nmsg msgmod version])
    save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $libprotobuf_c_CFLAGS $libnmsg_CFLAGS"
    AC_RUN_IFELSE(
        [AC_LANG_PROGRAM(
            [[
            #include <nmsg/msgmod_plugin.h>
            ]],
            [[
            if (NMSG_MSGMOD_VERSION == 9)
                return (0);
            else
                return (1);
            ]]
        )]
        ,
        AC_MSG_RESULT([yes])
        ,
        AC_MSG_FAILURE([nmsg msgmod version mismatch])
    )
    CFLAGS="$save_CFLAGS"
    ]
)
