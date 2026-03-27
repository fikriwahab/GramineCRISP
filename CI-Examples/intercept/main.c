#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(void) {
    printf("hai hai fasilkom\n");

    const char* buf = "gramine intercept test";
    int fd = open("a.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("open failed\n");
        return 1;
    }

    write(fd, buf, strlen(buf));
    fsync(fd);
    close(fd);

    printf("done\n");
    return 0;
}