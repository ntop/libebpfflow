odnl> Do not add anything above
AC_INIT([libebpfflow],[1.0.1])
dnl> Do not add anything above

AC_PROG_CPP
AC_PROG_CXX

# Use C++ language for tests
AC_LANG(C++)

# Libs required for compilation test below
LIBS="${LIBS} -lbcc"

AC_MSG_CHECKING([eBPF library new API version])
AC_TRY_COMPILE([
#include <bcc/BPF.h>
], [ ebpf::BPF *bpf;
	bpf->attach_kprobe((const char*)"", NULL, 0, BPF_PROBE_ENTRY);
], [ AC_MSG_RESULT(yes) AC_DEFINE_UNQUOTED(HAVE_NEW_EBPF, 1, [new BPF API]) ], [AC_MSG_RESULT(no)])

DATE=`date +"%Y-%m-%d"`
VERSION="1.0.${DATE}"

AC_DEFINE_UNQUOTED(EBPF_FLOW_VERSION, "${VERSION}", "Library version")

AC_SUBST(EBPF_LIBRARY_VERSION)
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)

AC_OUTPUT
