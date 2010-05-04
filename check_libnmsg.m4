###
### libnmsg
###
AC_ARG_WITH([libnmsg], AC_HELP_STRING([--with-libnmsg=DIR], [libnmsg installation path]), [], [ withval="yes" ])

# additional -I flags needed for compilation
libnmsg_cflags=""

# additional -l flags needed for linking
libnmsg_libs=""

# additional -L flags needed for linking
libnmsg_ldpath=""

# additional libtool objects
libnmsg_libadd=""

AC_DEFUN([MYAC_CHECK_LIBNMSG],
    AC_LINK_IFELSE(
        AC_LANG_PROGRAM(
            [[
            #include <nmsg.h>
            ]],
            [[
            nmsg_init();
            ]]
        )
        ,
        AC_MSG_RESULT([-lnmsg])
        AC_DEFINE([HAVE_NMSG], [1], [Define to 1 if libnmsg works.])
        ,
        AC_MSG_FAILURE([cannot find libnmsg library])
        libnmsg_cflags=""
        libnmsg_libs=""
        libnmsg_ldpath=""
        libnmsg_libadd=""
        )
)

AC_DEFUN([MYAC_CHECK_LIBNMSG_MSGMOD],
    AC_MSG_CHECKING([nmsg msgmod version])
    AC_RUN_IFELSE(
        AC_LANG_PROGRAM(
            [[
            #include <nmsg/msgmod_plugin.h>
            ]],
            [[
            if (NMSG_MSGMOD_VERSION == 7)
                return (0);
            else
                return (1);
            ]]
        )
        ,
        AC_MSG_RESULT([7])
        ,
        AC_MSG_FAILURE([nmsg msgmod version mismatch])
    )
)

AC_MSG_CHECKING([for libnmsg headers])
libnmsg_dir=""
if test "$withval" = "yes"; then
    withval="/usr /usr/local"
fi
for dir in $withval; do
    if test -f "$dir/include/nmsg.h"; then
        found_libnmsg_dir="yes"
        libnmsg_dir="$dir"
        if test "$dir" != "/usr"; then
            libnmsg_cflags="-I$dir/include"
        fi
        break
    fi
done

if test "$found_libnmsg_dir" = "yes"; then
    AC_MSG_RESULT([$dir])
else
    AC_MSG_ERROR([cannot find nmsg.h in $withval])
fi

AC_MSG_CHECKING([for libnmsg library])

if test "$libnmsg_dir" != "/usr"; then
    libnmsg_ldpath="-L$libnmsg_dir/lib"
fi

libnmsg_libs="-lnmsg"

save_cflags="$CFLAGS"
save_ldflags="$LDFLAGS"
save_libs="$LIBS"
CFLAGS="$CFLAGS $libnmsg_cflags"
LDFLAGS="$LDFLAGS $libnmsg_ldpath"
LIBS="$LIBS $libnmsg_libs"

MYAC_CHECK_LIBNMSG
MYAC_CHECK_LIBNMSG_MSGMOD

CFLAGS="$save_cflags"
LDFLAGS="$save_ldflags"
LIBS="$save_libs"

libnmsg_ldflags="$libnmsg_ldpath $libnmsg_libs"

AC_SUBST([libnmsg_cflags])  # add to _CFLAGS
AC_SUBST([libnmsg_ldflags]) # add to _LDFLAGS
