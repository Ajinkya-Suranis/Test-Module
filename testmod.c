#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/namei.h>
#include <linux/kallsyms.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/version.h>

#define	KMALLOC		kmalloc
#define	KFREE		kfree
#define	FILENAME	"/file1"
#define	VERSION_PATH	"/proc/version"
#define SYSMAP_PATH	"/boot/System.map-"
#define	MAXPATHLEN	256
#define	BUFSIZE		1024
#define	MAXLEN		256

unsigned long *syscall_table = NULL;
 
asmlinkage int (*original_open)(const char __user *filename, int flags, int mode);
 
asmlinkage int open_wrapper(const char __user *filename, int flags, int mode)
{
	struct inode		*ip, *target_ip;
	struct path		pth1, pth2;
	mm_segment_t		fs;
	int			error;

	error = kern_path(filename, LOOKUP_FOLLOW, &pth1);

	if (!error) {
		ip = pth1.dentry->d_inode;

		fs = get_fs();
		set_fs(get_fs());
		error = kern_path(FILENAME, LOOKUP_FOLLOW | LOOKUP_REVAL, &pth2);

		set_fs(fs);
		if (!error) {
			target_ip = pth2.dentry->d_inode;
			if (ip == target_ip) {
				return -EACCES;
			}
		}
	}
 
	return (*original_open)(filename, flags, mode);
}

char *
read_version_file(
	char		*buf)
{
	struct file	*fp = NULL;
	char		*version;

	fp = filp_open(VERSION_PATH, O_RDONLY, 0);

	if (fp == NULL || IS_ERR(fp)) {
		return NULL;
	}

	memset(buf, 0, MAXPATHLEN);

	vfs_read(fp, buf, 256, &fp->f_pos);

	version = strsep(&buf, " ");
	version = strsep(&buf, " ");
	version = strsep(&buf, " ");

	filp_close(fp, 0);

	return version;
}

static int
read_sysmap_file(
	char		*version)
{
	unsigned long	var;
	struct file	*fp = NULL;
	char		*buf = NULL, *str = NULL;
	char		*fname = NULL, *ptr;
	int		i = 0;

	buf = KMALLOC(BUFSIZE, GFP_KERNEL);
	if (buf == NULL) {
		return -1;
	}

	fname = KMALLOC(strlen(version) + strlen(SYSMAP_PATH) + 1, GFP_KERNEL);
	if (fname == NULL) {
		KFREE(buf);
		return -1;
	}

	memset(fname, 0, strlen(version) + strlen(SYSMAP_PATH) + 1);
	strncpy(fname, SYSMAP_PATH, strlen(SYSMAP_PATH));
	strncat(fname, version, strlen(version));


	fp = filp_open(fname, O_RDONLY, 0);

	if (fp == NULL || IS_ERR(fp)) {
		KFREE(buf);
		KFREE(fname);
		return -1;
	}

	memset(buf, 0x0, BUFSIZE);
	ptr = buf;

	while (vfs_read(fp, ptr + i, 1, &fp->f_pos) == 1) {
		if (ptr[i] == '\n' || i == 255) {
			i = 0;

			if (strstr(ptr, "sys_call_table") != NULL) {
				str = KMALLOC(MAXLEN, GFP_KERNEL);
				if (str == NULL) {
					KFREE(buf);
					KFREE(fname);
					filp_close(fp, 0);
					return -1;
				}

				memset(str, 0, MAXLEN);
				strncpy(str, strsep(&ptr, " "), MAXLEN);
				kstrtoul(str, 16, &var);
				syscall_table = (unsigned long *) var;
				break;
			}

			memset(buf, 0, MAXLEN);
			continue;
		}

		i++;
	}

	KFREE(buf);
	KFREE(fname);
	KFREE(str);

	filp_close(fp, 0);

	return 0;
}

static int
get_syscall_table_addr(void)
{
	char	*buf = NULL, *ver;

	buf = KMALLOC(MAXPATHLEN, GFP_KERNEL);
	if (buf == NULL) {
		return -1;
	}

	if ((ver = read_version_file(buf)) == NULL) {
		KFREE(buf);
		return -1;
	}

	if (read_sysmap_file(ver) != 0) {
		KFREE(buf);
		return -1;
	}

	KFREE(buf);
	return 0;
}


static int modinit(void)
{
	int	error = 0;
	mm_segment_t	fs; 

	printk(KERN_ALERT "New module loading..\n");
 
	write_cr0 (read_cr0 () & (~0x10000));

	fs = get_fs();
	set_fs(KERNEL_DS);
	if((error = get_syscall_table_addr()) != 0) {
		set_fs(fs);
		write_cr0 (read_cr0 () | 0x10000);
		return error;
	}
 
	original_open = (void *)syscall_table[__NR_open];
	syscall_table[__NR_open] = open_wrapper;

	set_fs(fs);
	write_cr0 (read_cr0 () | 0x10000);
 
	return 0;
}

static void modexit(void)
{
	write_cr0 (read_cr0 () & (~ 0x10000));

	syscall_table[__NR_open] = original_open;

	write_cr0 (read_cr0 () | 0x10000);
 
	printk(KERN_ALERT "MODULE EXIT\n");
 
	return;
}
 
module_init(modinit);
module_exit(modexit);
