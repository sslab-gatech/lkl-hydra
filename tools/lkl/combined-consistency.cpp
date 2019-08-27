#include <stdio.h>
#include <time.h>
#include <argp.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>

#include <vector>
#include <iostream>
#include <cstdio>
#include <string>
#include <stdexcept>
#include <experimental/filesystem>
#include <errno.h>
#include <signal.h>

#include <zlib.h>
#include <sys/sendfile.h>

#include "executor.hpp"
#include "Program.hpp"

#define PAGE_SIZE 4096
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
} while (0)

#define gettid() syscall(SYS_gettid)

namespace fs = std::experimental::filesystem;

static const char doc_executor[] = "File system fuzzing executor";
static const char args_doc_executor[] = "-t fstype -i fsimage_path -e emulator_path -d tmp_prefix -p program_path (-f) (-r) (-v)";

static struct argp_option options[] = {
    {"enable-printk", 'v', 0, 0, "show Linux printks"},
    {"filesystem-type", 't', "string", 0, "select filesystem type - mandatory"},
    {"filesystem-image", 'i', "string", 0, "path to the filesystem image - mandatory"},
    {"serialized-program", 'p', "string", 0, "serialized program - mandatory"},
    {"emulator-path", 'e', "string", 0, "path to the emulator script - mandatory"},
    {"log-path", 'l', "string", 0, "dir to store consistency testing logs - mandatory"},
    {"tmp-prefix-dir", 'd', "string", 0, "prefix for /tmp directory"},
    {"fifo-mode", 'f', 0, 0, "select fifo mode"},
    {"remove-image", 'r', 0, 0, "remove crashed image dump from disk"},
    {"no-sigraise", 'n', 0, 0, "Do not raise SIGUSR2"},
    {0},
};

static struct cl_args {
    int printk;
    int emul_verbose;
    int fifo_mode;
    int part;
    int rmimg;
    int no_sigraise;
    const char *fsimg_type;
    const char *fsimg_path;
    const char *prog_path;
    const char *emul_path;
    const char *log_dir;
    const char *tmp_prefix;
} cla;

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct cl_args *cla = (struct cl_args*)state->input;

    switch (key) {
        case 'v':
            cla->printk = 0;
            cla->emul_verbose = 1;
            break;
        case 't':
            cla->fsimg_type = arg;
            break;
        case 'i':
            cla->fsimg_path = arg;
            break;
        case 'p':
            cla->prog_path = arg;
            break;
        case 'e':
            cla->emul_path = arg;
            break;
        case 'l':
            cla->log_dir = arg;
            break;
        case 'd':
            cla->tmp_prefix = arg;
            break;
        case 'f':
            cla->fifo_mode = 1;
            break;
        case 'r':
            cla->rmimg = 1;
            break;
        case 'n':
            cla->no_sigraise = 1;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp_executor = {
    .options = options,
    .parser = parse_opt,
    .args_doc = args_doc_executor,
    .doc = doc_executor,
};

std::string check_output(const char* cmd) {
    //https://stackoverflow.com/questions/478898/how-to-execute-a-command-and-get-output-of-command-within-c-using-posix
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        return result;
        //throw std::runtime_error("popen() failed!");
    }
    try {
        while (!feof(pipe)) {
            if (fgets(buffer, 128, pipe) != NULL)
                result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        return result;
        //throw;
    }
    pclose(pipe);
    return result;
}

static void exec_syscall(Program *prog, Syscall *syscall) {

    long params[6];
    long ret;
    int cnt = 0;

    for (Arg *arg : syscall->args) {
        if (!arg->is_variable)
            params[cnt] = arg->value;
        else {
            Variable *v = prog->variables[arg->index];
            if (v->is_pointer() && v->value == 0)
                v->value = static_cast<uint8_t*>(malloc(v->size));
            params[cnt] = reinterpret_cast<long>(v->value);
        }
        cnt++;
    }

    ret = lkl_syscall(lkl_syscall_nr[syscall->nr], params);
    //ret = handle_syscalls(syscall->nr, params);
    if (syscall->ret_index != -1)
        prog->variables[syscall->ret_index]->value = reinterpret_cast<uint8_t*>(ret);

    // show_syscall(prog, syscall);
    // printf("ret: %ld\n", ret);
}

static void close_active_fds(Program *prog) {

    long params[6];

    for (int64_t fd_index : prog->active_fds) {
        params[0] = reinterpret_cast<long>(prog->variables[fd_index]->value);
        lkl_syscall(lkl_syscall_nr[SYS_close], params);
    }

}

struct arg_struct {
    long uffd;
    unsigned long base;
    void *buffer;
};

void *fault_handler_thread(void *arg) {
    struct arg_struct *args = (struct arg_struct *)arg;
    long uffd = args->uffd;
    void *buffer = args->buffer;
    unsigned long base = args->base;
    static struct uffd_msg msg;
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    for (;;) {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1)
            errExit("poll");

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0 || nread == -1) {
            fprintf(stderr, "error read on userfaultfd!\n");
            _exit(1);
        }

        unsigned long offset = (msg.arg.pagefault.address & ~(PAGE_SIZE - 1)) - base;
        uffdio_copy.src = (unsigned long)(buffer) + offset;
        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
        uffdio_copy.len = PAGE_SIZE;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1) _exit(1);
    }
}

void *userfault_init(void *image_buffer, size_t size) {
    long uffd;
    size_t len = size;
    pthread_t thr;
    struct uffdio_register uffdio_register;
    struct uffdio_api uffdio_api;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    void *buffer = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buffer == MAP_FAILED)
        errExit("mmap");

    uffdio_register.range.start = (unsigned long) buffer;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("register uffd");

    static struct arg_struct args;
    args.buffer = image_buffer;
    args.uffd = uffd;
    args.base = (unsigned long) buffer;
    int s = pthread_create(&thr, NULL, fault_handler_thread, (void *)(&args));
    if (s != 0)
        errExit("pthread_create");

    return buffer;
}

void hexdump (int offset, int size, void *addr)
{
    int i;
    unsigned char *p = (unsigned char*)addr;
    for (i = offset; i < offset+size; i++){
        if ((i % 4)==0) {
            if (i != offset)
                printf(" ");
        }
        if ((i % 32) == 0) {
            if (i != offset)
                printf("\n");
        }
        printf("%02x", p[i]);
    }
    printf("\n");
}

int serialize_buf (char* filename, void* buffer, size_t size)
{
    FILE* fd = fopen(filename, "w");
    if (fd == NULL) return -1;
    fwrite(buffer, 1, size, fd);
    fclose(fd);
    return 0;
}

static int searchdir(const char *fsimg_path, const char *path, FILE* fp_crashed);

static inline void fsimg_copy_stat(struct stat *st, struct lkl_stat *fst)
{
    st->st_dev = fst->st_dev;
    st->st_ino = fst->st_ino;
    st->st_mode = fst->st_mode;
    st->st_nlink = fst->st_nlink;
    st->st_uid = fst->st_uid;
    st->st_gid = fst->st_gid;
    st->st_rdev = fst->st_rdev;
    st->st_size = fst->st_size;
    st->st_blksize = fst->st_blksize;
    st->st_blocks = fst->st_blocks;
    st->st_atim.tv_sec = fst->lkl_st_atime;
    st->st_atim.tv_nsec = fst->st_atime_nsec;
    st->st_mtim.tv_sec = fst->lkl_st_mtime;
    st->st_mtim.tv_nsec = fst->st_mtime_nsec;
    st->st_ctim.tv_sec = fst->lkl_st_ctime;
    st->st_ctim.tv_nsec = fst->st_ctime_nsec;
}

static uint32_t get_data_chksum(const char *fsimg_path)
{
    long fsimg_fd;
    char buf[4096];
    int len;

    fsimg_fd = lkl_sys_open(fsimg_path, LKL_O_RDONLY, 0);
    if (fsimg_fd < 0){
        fprintf(stderr, "fsimg eror opening %s: %s\n", fsimg_path,
                lkl_strerror(fsimg_fd));
        return 0;
    }

    uint32_t crc = crc32(0L, Z_NULL, 0);

    do {
        len = lkl_sys_read(fsimg_fd, buf, sizeof(buf));
        if (len > 0) {
            crc = crc32(crc, (unsigned char*)buf, len);
        }
        if (len < 0) {
            fprintf(stderr, "error reading file %s\n", fsimg_path);
            return 0;
        }
    } while (len > 0);

    lkl_sys_close(fsimg_fd);
    return crc;
}


static int do_entry(const char *fsimg_path, const char *path,
           const struct lkl_linux_dirent64 *de, FILE* fp_crashed)
{
    char fsimg_new_path[PATH_MAX], new_path[PATH_MAX];
    struct lkl_stat fsimg_stat;
    struct stat stat;
    int ftype;
    long ret;
    uint32_t crc = 0;
    char symlink_path[4096] = { 0, };
    ssize_t buflen, keylen, vallen;
    char *buf, *key, *val;
    char xattrstr[16384] = { 0, };
    int offset = 0;

    snprintf(new_path, sizeof(new_path), "%s/%s", path, de->d_name);
    snprintf(fsimg_new_path, sizeof(fsimg_new_path), "%s/%s", fsimg_path,
        de->d_name);

    ret = lkl_sys_lstat(fsimg_new_path, &fsimg_stat);
    if (ret) {
        fprintf(stderr, "fsimg lstat(%s) error: %s\n",
            path, lkl_strerror(ret));
        return ret;
    }

    fsimg_copy_stat(&stat, &fsimg_stat);

    ftype = stat.st_mode & S_IFMT;
    int ftype_converted = 0;
    if (ftype == 0x8000) {
        ftype_converted = 1; // regular file
        crc = get_data_chksum(fsimg_new_path); // crc32 checksum

        buflen = lkl_sys_listxattr(fsimg_new_path, NULL, 0);
        if (buflen == -1) {
            fprintf(stderr, "listxattr(%s) error\n", fsimg_new_path);
            return buflen;
        }
        else if (buflen == 0){
            // no xattr
        }
        else {
            buf = (char*)malloc(buflen);
            buflen = lkl_sys_listxattr(fsimg_new_path, buf, buflen);
            key = buf;
            while (buflen > 0) {
                vallen = lkl_sys_getxattr(fsimg_new_path, key, NULL, 0);
                if (vallen > 0) {
                    val = (char*)malloc(vallen + 1);
                    vallen = lkl_sys_getxattr(fsimg_new_path, key, val, vallen);
                    offset += sprintf(xattrstr + offset, "%s: ", key);
                    memcpy(xattrstr + offset, val, vallen);
                    offset += vallen;
                    offset += sprintf(xattrstr + offset, ", ");
                    free(val);
                }
                keylen = strlen(key) + 1;
                buflen -= keylen;
                key += keylen;
            }
            free(buf);
        }
    }
    else if (ftype == 0x4000) {
        ftype_converted = 2; // directory

        buflen = lkl_sys_listxattr(fsimg_new_path, NULL, 0);
        if (buflen == -1) {
            fprintf(stderr, "listxattr(%s) error\n", fsimg_new_path);
            return buflen;
        }
        else if (buflen == 0){
            // no xattr
        }
        else {
            buf = (char*)malloc(buflen);
            buflen = lkl_sys_listxattr(fsimg_new_path, buf, buflen);
            key = buf;
            while (buflen > 0) {
                vallen = lkl_sys_getxattr(fsimg_new_path, key, NULL, 0);
                if (vallen > 0) {
                    val = (char*)malloc(vallen + 1);
                    vallen = lkl_sys_getxattr(fsimg_new_path, key, val, vallen);
                    offset += sprintf(xattrstr + offset, "%s: ", key);
                    memcpy(xattrstr + offset, val, vallen);
                    offset += vallen;
                    offset += sprintf(xattrstr + offset, ", ");
                    free(val);
                }
                keylen = strlen(key) + 1;
                buflen -= keylen;
                key += keylen;
            }
            free(buf);
        }
    }
    else if (ftype == 0xA000) {
        ftype_converted = 3; // symbolic link
        ret = lkl_sys_readlink(fsimg_new_path, symlink_path, sizeof(symlink_path));
        if (ret < 0) {
            fprintf(stderr, "fsimg readlink(%s) error: %s\n",
                    fsimg_new_path, lkl_strerror(ret));
            return ret;
        }
    }
    else if (ftype == 0x1000) {
        ftype_converted = 4; // fifo file
    }

    char record[16384] = { 0, };
    int wnum = sprintf(record, "%s\t%d\t%zu\t%zu\t%zu\t%zu\t%zu\t%o\t%u\t%s\t",
            new_path, ftype_converted,
            stat.st_ino, stat.st_nlink, stat.st_size, stat.st_blksize,
            stat.st_blocks, stat.st_mode & ~S_IFMT,
            crc, symlink_path);
    memcpy(record + wnum, xattrstr, offset);
    memcpy(record + wnum + offset, "\n", strlen("\n"));
    fwrite(record, sizeof(char), wnum + offset + strlen("\n"), fp_crashed);

    switch (ftype) {
    case S_IFREG:
        break;
    case S_IFDIR:
        ret = searchdir(fsimg_new_path, new_path, fp_crashed);
        break;
    case S_IFLNK:
        break;
    case S_IFIFO:
        break;
    case S_IFSOCK:
    case S_IFBLK:
    case S_IFCHR:
    default:
        printf("skipping %s: unsupported entry type %d\n", new_path,
             ftype);
    }

    return 0;
}

static int searchdir(const char *fsimg_path, const char *path, FILE* fp_crashed)
{
    long ret, fd;
    char buf[1024], *pos;
    long buf_len;

    fd = lkl_sys_open(fsimg_path, LKL_O_RDONLY | LKL_O_DIRECTORY, 0);
    if (fd < 0) {
        fprintf(stderr, "failed to open dir %s: %s", fsimg_path,
            lkl_strerror(fd));
        return fd;
    }

    do {
        struct lkl_linux_dirent64 *de;
        de = (struct lkl_linux_dirent64 *) buf;
        buf_len = lkl_sys_getdents64(fd, de, sizeof(buf));
        if (buf_len < 0) {
            fprintf(stderr, "gentdents64 error: %s\n",
                lkl_strerror(buf_len));
            break;
        }

        for (pos = buf; pos - buf < buf_len; pos += de->d_reclen) {
            de = (struct lkl_linux_dirent64 *)pos;
            if (!strcmp(de->d_name, ".") ||
               !strcmp(de->d_name, ".."))
                continue;

            ret = do_entry(fsimg_path, path, de, fp_crashed);
            if (ret)
                goto out;
        }
    } while (buf_len > 0);

out:
    lkl_sys_close(fd);
    return ret;
}


extern "C" void __afl_manual_init(void **buffer, size_t *size);
extern uint32_t __afl_in_trace;

int main(int argc, char **argv)
{
    struct lkl_disk disk;
    long ret;
    char mpoint[32];
    unsigned int disk_id;

    void *image_buffer;
    size_t size;
    struct stat st;

    int fd;
    int verbose = 0;

    cla.no_sigraise = 0;
    if (argp_parse(&argp_executor, argc, argv, 0, 0, &cla) < 0)
        return -1;

    if (!cla.printk)
        lkl_host_ops.print = NULL;

    const char *mount_options = NULL;
    if (!strcmp(cla.fsimg_type, "btrfs"))
        mount_options = "thread_pool=1";
    else if (!strcmp(cla.fsimg_type, "gfs2"))
        mount_options = "acl";
    else if (!strcmp(cla.fsimg_type, "reiserfs"))
        mount_options = "acl,user_xattr";
    else if (!strcmp(cla.fsimg_type, "ext4"))
        mount_options = "errors=remount-ro";

    if (!cla.fsimg_path) {
        __afl_manual_init(&image_buffer, &size);
    } else {
        __afl_manual_init(NULL, NULL);
        lstat(cla.fsimg_path, &st);
        fd = open(cla.fsimg_path, O_RDWR);
        if (fd < 0) return -1;
        image_buffer = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        close(fd);
        size = st.st_size;
    }

    disk.ops = NULL;
    disk.buffer = userfault_init(image_buffer, size);
    disk.capacity = size;

    ret = lkl_disk_add(&disk);
    if (ret < 0) {
        fprintf(stderr, "can't add disk: %s\n", lkl_strerror(ret));
        lkl_sys_halt();
        return -1;
    }
    disk_id = ret;

    lkl_start_kernel(&lkl_host_ops, "mem=128M");

    __afl_in_trace = 1;

    std::string prefix;
    if (cla.tmp_prefix)
        prefix = cla.tmp_prefix;
    else
        prefix = "";
    std::string tmpstr = prefix + std::tmpnam(nullptr) + "-" + std::to_string(getpid());
    char const* tmplogname = tmpstr.c_str();

    ret = lkl_mount_dev(disk_id, cla.part, cla.fsimg_type, 0,
            mount_options, mpoint, sizeof(mpoint));
    if (ret) {
        fprintf(stderr, "can't mount base img disk: %s\n", lkl_strerror(ret));
        lkl_sys_halt();
        return -1;
    }

    ret = lkl_sys_chdir(mpoint);
    if (ret) {
        fprintf(stderr, "can't chdir to %s: %s\n", mpoint,
                lkl_strerror(ret));
        lkl_umount_dev(disk_id, cla.part, 0, 1000);
        lkl_sys_halt();
        return -1;
    }

    Program *prog = Program::deserialize(cla.prog_path, true);
    int callcnt = 1;
    for (Syscall *syscall : prog->syscalls) {
        if (verbose)
            fprintf(stdout, "#%d", callcnt);
        exec_syscall(prog, syscall);
        callcnt++;
    }

    std::string imgname_s = tmpstr + ".img";
    char const* imgname = imgname_s.c_str();
    int fd_crashed = open(imgname, O_RDWR | O_CREAT, 0664);
    ret = write(fd_crashed, disk.buffer, disk.capacity);
    fsync(fd_crashed);
    close(fd_crashed);

    ret = lkl_sys_chdir("/");

    close_active_fds(prog);
    ret = lkl_umount_dev(disk_id, cla.part, 0, 1000);
    ret = lkl_disk_remove(disk);

    unsigned int disk_id_cr;
    struct lkl_disk disk_cr;
    char mpoint_cr[32];

    disk_cr.ops = NULL;
    // disk_cr.buffer = disk.buffer; // memory of crashed image

    fd = open(imgname, O_RDWR);
    if (fd < 0) return -1;
    void* image_buffer2 = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    disk_cr.buffer = userfault_init(image_buffer2, size);
    disk_cr.capacity = size;

    ret = lkl_disk_add(&disk_cr);
    if (ret < 0) {
        fprintf(stderr, "can't add crashed disk: %s\n", lkl_strerror(ret));
        lkl_sys_halt();
        unlink(imgname);
        return -1;
    }
    disk_id_cr = ret;

    // Mount crashed disk, and traverse
    ret = lkl_mount_dev(disk_id_cr, cla.part, cla.fsimg_type, 0,
            mount_options, mpoint_cr, sizeof(mpoint_cr));
    if (ret) {
        fprintf(stderr, "can't mount crashed disk: %s\n", lkl_strerror(ret));
        lkl_umount_dev(disk_id, cla.part, 0, 1000);
        lkl_sys_halt();
        unlink(imgname);
        return -1;
    }

    ret = lkl_sys_chdir(mpoint_cr);
    if (ret) {
        fprintf(stderr, "can't chdir to %s: %s\n", mpoint_cr,
                lkl_strerror(ret));
        lkl_umount_dev(disk_id, cla.part, 0, 1000);
        lkl_umount_dev(disk_id_cr, cla.part, 0, 1000);
        lkl_sys_halt();
        unlink(imgname);
        return -1;
    }

    // Traverse crashed image, and write metadata to log file
    FILE* fp_crashed = fopen(tmplogname, "w");
    ret = searchdir(mpoint_cr, ".", fp_crashed);
    fclose(fp_crashed);

    char emul_command[1024];
    if (cla.emul_verbose) {
        if (cla.fifo_mode)
            sprintf(emul_command, "%s -i %s -t %s -p %s -c %s -v -f 2>&1",
                cla.emul_path, cla.fsimg_path, cla.fsimg_type, cla.prog_path, tmplogname);
        else
            sprintf(emul_command, "%s -i %s -t %s -p %s -c %s -v 2>&1",
                cla.emul_path, cla.fsimg_path, cla.fsimg_type, cla.prog_path, tmplogname);
    } else {
        if (cla.fifo_mode)
            sprintf(emul_command, "%s -i %s -t %s -p %s -c %s -f 2>&1",
                cla.emul_path, cla.fsimg_path, cla.fsimg_type, cla.prog_path, tmplogname);
        else
            sprintf(emul_command, "%s -i %s -t %s -p %s -c %s 2>&1",
                cla.emul_path, cla.fsimg_path, cla.fsimg_type, cla.prog_path, tmplogname);
    }

    std::string tmpname_nopath = tmpstr.substr(
            prefix.length() + 4,
            tmpstr.length()-4
            );
    if (cla.emul_verbose)
        std::cout << "emulator command: " << emul_command << std::endl;

    std::string res = check_output(emul_command);
    if (cla.emul_verbose)
        std::cout << res << std::endl;

    std::string debugpath = prefix + "/tmp/emuldebug/";
    int bug = 0;
    if (res.length() == 0) { // no bug
        if (cla.emul_verbose)
            std::cout << "no bug" << std::endl;
        unlink(tmplogname);
        unlink(imgname);
    } else if (res.length() > 0 && res.find("Traceback") != std::string::npos) {
        // It must be an python error, coming from the emulator.
        // Save the error msg, serialized prog, and log for debugging.
        std::string log_progpath;
        log_progpath = debugpath + tmpname_nopath + "-prog";

        int fd_log_progpath = open(log_progpath.c_str(), O_RDWR | O_CREAT, 0644);
        int fd_prog_path = open(cla.prog_path, O_RDONLY);
        struct stat st;
        fstat(fd_prog_path, &st);
        ret = sendfile(fd_log_progpath, fd_prog_path, NULL, st.st_size);

        std::string debuglogname = debugpath + tmpname_nopath;
        rename(tmplogname, debuglogname.c_str());
        unlink(imgname);
        sync();

        std::string errname = debugpath + tmpname_nopath + "-err";
        int fd_errlog = open(errname.c_str(), O_CREAT | O_WRONLY , 0644);
        write(fd_errlog, res.c_str(), res.length());
        fsync(fd_errlog);
        close(fd_errlog);

    } else {
        if (cla.emul_verbose)
            std::cout << "Bug after all" << std::endl;
        bug = 1;
        // save the first log before fsck
        std::string logpath;
        logpath += cla.log_dir;
        logpath += tmpname_nopath;
        ret = rename(tmplogname, logpath.c_str());

        std::string log_progpath; // to save the serialized program
        log_progpath = logpath + "-prog";

        int fd_log_progpath = open(log_progpath.c_str(), O_RDWR | O_CREAT, 0644);
        int fd_prog_path = open(cla.prog_path, O_RDONLY);

        struct stat st;
        fstat(fd_prog_path, &st);
        ret = sendfile(fd_log_progpath, fd_prog_path, NULL, st.st_size);

        std::string final_crashed_imgfile = logpath + ".img";
        if (cla.rmimg)
            unlink(imgname);
        else
            rename(imgname, final_crashed_imgfile.c_str());
        sync();

        close(fd_log_progpath);
        close(fd_prog_path);

        ret = lkl_sys_chdir("/");
    }

    close_active_fds(prog);
    ret = lkl_sys_chdir("/");
    if (ret) {
        fprintf(stderr, "can't chdir to %s: %s\n", mpoint_cr,
                lkl_strerror(ret));
        lkl_umount_dev(disk_id, cla.part, 0, 1000);
        lkl_umount_dev(disk_id_cr, cla.part, 0, 1000);
        lkl_sys_halt();
        return -1;
    }
    lkl_umount_dev(disk_id, cla.part, 0, 1000);
    lkl_umount_dev(disk_id_cr, cla.part, 0, 1000);

    lkl_disk_remove(disk);
    lkl_disk_remove(disk_cr);
    lkl_sys_halt();
    munmap(image_buffer, size);

    if (cla.emul_verbose)
        return 0;
    if (bug) {
        //system("rm /tmp/file*"); // ad-hoc approach to clean up tmp directory
        puts("bug!");
        // use SIGUSR2 for notifying the fuzzer of a crash consistency bug
        fflush(NULL);
        if (!cla.no_sigraise)
            raise(SIGUSR2);
    }

    __afl_in_trace = 0;

    return 0;
}
