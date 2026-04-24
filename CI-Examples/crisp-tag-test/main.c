#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    printf("crisp-tag-test: creating PF files\n");

    const char* paths[] = {"/crisp/a.dat", "/crisp/b.dat"};
    const char* contents[] = {"hello from a", "hello from b"};

    for (int i = 0; i < 2; i++) {
        int fd = open(paths[i], O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            printf("  FAIL open %s\n", paths[i]);
            return 1;
        }
        write(fd, contents[i], strlen(contents[i]));
        fsync(fd);
        close(fd);
        printf("  wrote %s\n", paths[i]);
    }
    return 0;
}
