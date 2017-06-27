#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <malloc.h>
#include <stdbool.h>
#include <string.h>

int
main(
	int		argc,
	char		*argv[])
{
	int		fd;

	if ((fd = open("/file1", O_RDWR)) < 0) {
		fprintf(stderr, "Open failed.\n");
		return 1;
	} else {
		fprintf(stdout, "Open succeeded.\n");
		return 0;
	}

	return 0;
}
