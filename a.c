#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <utime.h>
#include <errno.h>
#include <string.h>
#include <time.h>

int main() {
    const char *filename = "testfile.tmp";
    int fd = open(filename, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    write(fd, "test", 4);
    close(fd);

    // Make file read-only
    if (chmod(filename, 0044) < 0) {
        perror("chmod");
        unlink(filename);
        return 1;
    }

    // Set utime to now + 60 seconds
    struct utimbuf new_times;
    new_times.actime = time(NULL) + 60;    // access time
    new_times.modtime = time(NULL) + 60;   // modification time

    if (utime("/tmp/1", NULL) == 0) {
        printf("SUCCESS: utime() updated timestamps on read-only file.\n");
    } else {
        printf("FAILURE: utime() failed with errno=%d (%s)\n", errno, strerror(errno));
    }

    // Clean up
    unlink(filename);
    return 0;
}

