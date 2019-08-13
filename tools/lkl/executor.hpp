#ifndef _EXECUTOR_HPP
#define _EXECUTOR_HPP

extern "C"
{
#include <lkl.h>
#include <lkl_host.h>
}

long lkl_syscall_nr[] = {
	63, 	// read
	64, 	// write
	-1, 	// open
	57, 	// close
	1038, 	// newstat
	80, 	// newfstat
	1039, 	// newlstat
	-1, 	// poll
	-1, 	// lseek
	222, 	// mmap
	226, 	// mprotect
	215, 	// munmap
	214, 	// brk
	134, 	// rt_sigaction
	135, 	// rt_sigprocmask
	139, 	// rt_sigreturn
	29, 	// ioctl
	67, 	// pread64
	68, 	// pwrite64
	65, 	// readv
	66, 	// writev
	-1, 	// access
	1040, 	// pipe
	-1, 	// select
	124, 	// sched_yield
	216, 	// mremap
	227, 	// msync
	232, 	// mincore
	233, 	// madvise
	194, 	// shmget
	196, 	// shmat
	195, 	// shmctl
	23, 	// dup
	1041, 	// dup2
	-1, 	// pause
	101, 	// nanosleep
	102, 	// getitimer
	-1, 	// alarm
	103, 	// setitimer
	172, 	// getpid
	71, 	// sendfile64
	198, 	// socket
	203, 	// connect
	202, 	// accept
	206, 	// sendto
	207, 	// recvfrom
	211, 	// sendmsg
	212, 	// recvmsg
	210, 	// shutdown
	200, 	// bind
	201, 	// listen
	204, 	// getsockname
	205, 	// getpeername
	199, 	// socketpair
	208, 	// setsockopt
	209, 	// getsockopt
	220, 	// clone
	-1, 	// fork
	-1, 	// vfork
	221, 	// execve
	93, 	// exit
	260, 	// wait4
	129, 	// kill
	160, 	// newuname
	190, 	// semget
	193, 	// semop
	191, 	// semctl
	197, 	// shmdt
	186, 	// msgget
	189, 	// msgsnd
	188, 	// msgrcv
	187, 	// msgctl
	25, 	// fcntl
	32, 	// flock
	82, 	// fsync
	83, 	// fdatasync
	45, 	// truncate
	46, 	// ftruncate
	-1, 	// getdents
	17, 	// getcwd
	49, 	// chdir
	50, 	// fchdir
	-1, 	// rename
	-1, 	// mkdir
	-1, 	// rmdir
	-1, 	// creat
	-1, 	// link
	-1, 	// unlink
	-1, 	// symlink
	-1, 	// readlink
	-1, 	// chmod
	52, 	// fchmod
	1029, 	// chown
	55, 	// fchown
	1032, 	// lchown
	166, 	// umask
	169, 	// gettimeofday
	163, 	// getrlimit
	165, 	// getrusage
	179, 	// sysinfo
	153, 	// times
	117, 	// ptrace
	174, 	// getuid
	116, 	// syslog
	176, 	// getgid
	146, 	// setuid
	144, 	// setgid
	175, 	// geteuid
	177, 	// getegid
	154, 	// setpgid
	173, 	// getppid
	-1, 	// getpgrp
	157, 	// setsid
	145, 	// setreuid
	143, 	// setregid
	158, 	// getgroups
	159, 	// setgroups
	147, 	// setresuid
	148, 	// getresuid
	149, 	// setresgid
	150, 	// getresgid
	155, 	// getpgid
	151, 	// setfsuid
	152, 	// setfsgid
	156, 	// getsid
	90, 	// capget
	91, 	// capset
	136, 	// rt_sigpending
	137, 	// rt_sigtimedwait
	138, 	// rt_sigqueueinfo
	133, 	// rt_sigsuspend
	132, 	// sigaltstack
	-1, 	// utime
	1027, 	// mknod
	-1, 	// obsolete
	92, 	// personality
	-1, 	// ustat
	-1, 	// statfs
	-1, 	// fstatfs
	-1, 	// sysfs
	141, 	// getpriority
	140, 	// setpriority
	118, 	// sched_setparam
	121, 	// sched_getparam
	119, 	// sched_setscheduler
	120, 	// sched_getscheduler
	125, 	// sched_get_priority_max
	126, 	// sched_get_priority_min
	127, 	// sched_rr_get_interval
	228, 	// mlock
	229, 	// munlock
	230, 	// mlockall
	231, 	// munlockall
	58, 	// vhangup
	-1, 	// modify_ldt
	41, 	// pivot_root
	-1, 	// sysctl
	167, 	// prctl
	-1, 	// arch_prctl
	171, 	// adjtimex
	164, 	// setrlimit
	51, 	// chroot
	81, 	// sync
	89, 	// acct
	170, 	// settimeofday
	40, 	// mount
	39, 	// umount
	224, 	// swapon
	225, 	// swapoff
	142, 	// reboot
	161, 	// sethostname
	162, 	// setdomainname
	-1, 	// iopl
	-1, 	// ioperm
	-1, 	// obsolete
	105, 	// init_module
	106, 	// delete_module
	-1, 	// obsolete
	-1, 	// obsolete
	60, 	// quotactl
	-1, 	// obsolete
	-1, 	// obsolete
	-1, 	// obsolete
	-1, 	// obsolete
	-1, 	// obsolete
	-1, 	// obsolete
	178, 	// gettid
	213, 	// readahead
	5, 	// setxattr
	6, 	// lsetxattr
	7, 	// fsetxattr
	8, 	// getxattr
	9, 	// lgetxattr
	10, 	// fgetxattr
	11, 	// listxattr
	12, 	// llistxattr
	13, 	// flistxattr
	14, 	// removexattr
	15, 	// lremovexattr
	16, 	// fremovexattr
	130, 	// tkill
	-1, 	// time
	98, 	// futex
	122, 	// sched_setaffinity
	123, 	// sched_getaffinity
	-1, 	// obsolete
	0, 	// io_setup
	1, 	// io_destroy
	4, 	// io_getevents
	2, 	// io_submit
	3, 	// io_cancel
	-1, 	// obsolete
	18, 	// lookup_dcookie
	1042, 	// epoll_create
	-1, 	// obsolete
	-1, 	// obsolete
	234, 	// remap_file_pages
	61, 	// getdents64
	96, 	// set_tid_address
	128, 	// restart_syscall
	192, 	// semtimedop
	223, 	// fadvise64
	107, 	// timer_create
	110, 	// timer_settime
	108, 	// timer_gettime
	109, 	// timer_getoverrun
	111, 	// timer_delete
	112, 	// clock_settime
	113, 	// clock_gettime
	114, 	// clock_getres
	115, 	// clock_nanosleep
	94, 	// exit_group
	-1, 	// epoll_wait
	21, 	// epoll_ctl
	131, 	// tgkill
	1037, 	// utimes
	-1, 	// obsolete
	235, 	// mbind
	237, 	// set_mempolicy
	236, 	// get_mempolicy
	180, 	// mq_open
	181, 	// mq_unlink
	182, 	// mq_timedsend
	183, 	// mq_timedreceive
	184, 	// mq_notify
	185, 	// mq_getsetattr
	104, 	// kexec_load
	95, 	// waitid
	217, 	// add_key
	218, 	// request_key
	219, 	// keyctl
	30, 	// ioprio_set
	31, 	// ioprio_get
	1043, 	// inotify_init
	27, 	// inotify_add_watch
	28, 	// inotify_rm_watch
	238, 	// migrate_pages
	56, 	// openat
	34, 	// mkdirat
	33, 	// mknodat
	54, 	// fchownat
	-1, 	// futimesat
	79, 	// newfstatat
	35, 	// unlinkat
	38, 	// renameat
	37, 	// linkat
	36, 	// symlinkat
	78, 	// readlinkat
	53, 	// fchmodat
	48, 	// faccessat
	72, 	// pselect6
	73, 	// ppoll
	97, 	// unshare
	99, 	// set_robust_list
	100, 	// get_robust_list
	76, 	// splice
	77, 	// tee
	84, 	// sync_file_range
	75, 	// vmsplice
	239, 	// move_pages
	88, 	// utimensat
	22, 	// epoll_pwait
	1045, 	// signalfd
	85, 	// timerfd_create
	1044, 	// eventfd
	47, 	// fallocate
	86, 	// timerfd_settime
	87, 	// timerfd_gettime
	242, 	// accept4
	74, 	// signalfd4
	19, 	// eventfd2
	20, 	// epoll_create1
	24, 	// dup3
	59, 	// pipe2
	26, 	// inotify_init1
	69, 	// preadv
	70, 	// pwritev
	240, 	// rt_tgsigqueueinfo
	241, 	// perf_event_open
	243, 	// recvmmsg
	262, 	// fanotify_init
	263, 	// fanotify_mark
	261, 	// prlimit64
	264, 	// name_to_handle_at
	265, 	// open_by_handle_at
	266, 	// clock_adjtime
	267, 	// syncfs
	269, 	// sendmmsg
	268, 	// setns
	168, 	// getcpu
	270, 	// process_vm_readv
	271, 	// process_vm_writev
	272, 	// kcmp
	273, 	// finit_module
	274, 	// sched_setattr
	275, 	// sched_getattr
	276, 	// renameat2
	277, 	// seccomp
	278, 	// getrandom
	279, 	// memfd_create
	-1, 	// kexec_file_load
	280, 	// bpf
	281, 	// execveat
	282, 	// userfaultfd
	283, 	// membarrier
	284, 	// mlock2
	285, 	// copy_file_range
	286, 	// preadv2
	287, 	// pwritev2
	288, 	// pkey_mprotect
	289, 	// pkey_alloc
	290, 	// pkey_free
	291 	// statx
};

enum {
	NR_open =		2,
	NR_lseek =		8,
	NR_access =		21,
	NR_rename =		82,
	NR_mkdir =		83,
	NR_rmdir =		84,
	NR_link =		86,
	NR_unlink =		87,
	NR_symlink =	88,
	NR_readlink =	89,
	NR_chmod =		90,
	NR_statfs =		137,
	NR_fstatfs =	138,
};

static long handle_deprecated_syscalls(long nr, long *params) {
	long ret = 0;

	switch(nr) {
	case NR_open:
		ret = lkl_sys_open((const char *)params[0],
						   (int)params[1], (int)params[2]);
		break;
	case NR_lseek:
		ret = lkl_sys_lseek((unsigned int)params[0], (off_t)params[1],
							(unsigned int)params[2]);
		break;
	case NR_rename:
		ret = lkl_sys_rename((const char *)params[0], (const char *)params[1]);
		break;
	case NR_access:
		ret = lkl_sys_access((const char *)params[0], (int)params[1]);
		break;
	case NR_statfs:
		ret = lkl_sys_statfs((const char *)params[0],
							 (struct lkl_statfs *)params[1]);
		break;
	case NR_fstatfs:
		ret = lkl_sys_fstatfs((int)params[0], (struct lkl_statfs*)params[1]);
		break;
	case NR_mkdir:
		ret = lkl_sys_mkdir((const char *)params[0], (mode_t)params[1]);
		break;
	case NR_rmdir:
		ret = lkl_sys_rmdir((const char *)params[0]);
		break;
	case NR_link:
		ret = lkl_sys_link((const char *)params[0], (const char *)params[1]);
		break;
	case NR_unlink:
		ret = lkl_sys_unlink((const char *)params[0]);
		break;
	case NR_symlink:
		ret = lkl_sys_symlink((const char *)params[0], (const char *)params[1]);
		break;
	case NR_readlink:
		ret = lkl_sys_readlink((const char *)params[0], (char *)params[1],
							   (size_t)params[2]);
		break;
	case NR_chmod:
		ret = lkl_sys_chmod((const char *)params[0], (mode_t)params[1]);
		break;
	}
	return ret;
}

static long handle_syscalls(long nr, long *params) {

	// hanlde deprecated syscalls in an ad-hoc fashion
	if (lkl_syscall_nr[nr] == -1)
		return handle_deprecated_syscalls(nr, params);

	return lkl_syscall(lkl_syscall_nr[nr], params);
}

#endif
