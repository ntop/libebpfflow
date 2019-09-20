odnl> Do not add anything above
AC_INIT([libebpfflow],[1.0.1])
dnl> Do not add anything above

AC_PROG_CPP
AC_PROG_CXX

# Use C++ language for tests
AC_LANG(C++)

AC_CHECK_LIB([bcc], [printf])
if test "x$ac_cv_lib_bcc_printf" != x""yes; then
   echo "Please install the bcc-dev(el) package and try again"
   exit
fi

# Libs required for compilation test below
LIBS="${LIBS} -lbcc"

AC_MSG_CHECKING([eBPF library new API version])
AC_TRY_COMPILE([
#include <bcc/BPF.h>
], [ ebpf::BPF *bpf;
	bpf->attach_kprobe((const char*)"", NULL, 0, BPF_PROBE_ENTRY);
], [ AC_MSG_RESULT(yes) AC_DEFINE_UNQUOTED(HAVE_NEW_EBPF, 1, [new BPF API]) ], [AC_MSG_RESULT(no)])

DATE=`date +"%y%m%d"`
VERSION="1.0.${DATE}"

AC_DEFINE_UNQUOTED(EBPF_FLOW_VERSION, "${VERSION}", "Library version")

AC_CHECK_LIB([json-c], [json_object_new_object])
if test "x$ac_cv_lib_json_c_json_object_new_object" != "xyes"; then
   echo "Please install the json-c package and try again"
   exit
fi

AC_CHECK_LIB([curl], [curl_easy_init])
if test "x$ac_cv_lib_curl_curl_easy_init" != "xyes"; then
   echo "Please install the libcurl (libcurl4-openssl-dev) package and try again"
   exit
fi

AC_CHECK_LIB([zmq], [zmq_socket_monitor])
if test "x$ac_cv_lib_zmq_zmq_socket_monitor" != "xyes"; then :
   echo "Please install the ZMQ package and try again"
   exit
fi

if ! which pkg-config >/dev/null ; then
   AC_MSG_ERROR([Missing pkg-config: please check README.md])
fi


AC_CHECK_LIB([json-c], json_object_new_double_s, AC_DEFINE_UNQUOTED(HAVE_DOUBLES, 1, [json-c has json_object_new_double_s]))

AC_SUBST(EBPF_LIBRARY_VERSION)
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)

AC_OUTPUT
