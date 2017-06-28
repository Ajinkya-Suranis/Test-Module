#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <malloc.h>
#include <stdbool.h>
#include <string.h>

/*
 * The purpose of this program is to test the
 * 'open' system call interception.
 * This interception is enabled by loading
 * the 'testmod' kernel module.
 * Please refer to the README for more details.
 *
 * This program tries to open the file name
 * passed as an argument and simply reports success
 * or failure.
 * The file name should be the same as the name which
 * is passed to the 'insmod' while loading the module
 * 'testmod'.
 * If the module is successfully loaded, then program
 * should report failre and vice-versa.
 */

int
main(
	int		argc,
	char		*argv[])
{
	int		fd;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file_name>\n", argv[1]);
		return 1;
	}

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		fprintf(stderr, "Open failed.\n");
		return 1;
	} else {
		fprintf(stdout, "Open succeeded.\n");
		close(fd);
	}

	return 0;
}
