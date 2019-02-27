odnl> Do not add anything above
AC_INIT([libebpfflow],[1.0.1])
dnl> Do not add anything above

AC_PROG_CPP
AC_PROG_CXX

AC_MSG_CHECKING([eBPF library new API version])
AC_TRY_RUN([
#include <pthread.h>

int main() {
	ebpf::BPF *bpf;
 	bpf->attach_kprobe((const char*)"", NULL, 0, 0:
        return 0;
}
], [ AC_MSG_RESULT(yes) AC_DEFINE_UNQUOTED(HAVE_NEW_EBPF, 1, [new BPF API]) ], [AC_MSG_RESULT(no)]
)

DATE=`date +"%Y-%m-%d"`
VERSION="1.0.${DATE}"

AC_DEFINE_UNQUOTED(EBPF_FLOW_VERSION, "${VERSION}", "Library version")

AC_SUBST(EBPF_LIBRARY_VERSION)
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)

AC_OUTPUT
