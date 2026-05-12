#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// exercises the CRISP hooks: write, fsync, close each tracked PF, then exit
// a.dat content comes from argv[1] when given (handy for the tag-mismatch test), b.dat is always "beta"
int main(int argc, char** argv) {
    const char* a_content = (argc > 1) ? argv[1] : "alpha";

    struct { const char* path; const char* content; } files[] = {
        {"/crisp/a.dat", a_content},
        {"/crisp/b.dat", "beta"},
    };

    for (int i = 0; i < 2; i++) {
        int fd = open(files[i].path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        // int fd = open(files[i].path, O_RDONLY);   // read-only variant: also drop the write and fsync below
        if (fd < 0) {
            printf("crisp-tag-test: FAIL open %s\n", files[i].path);
            return 1;
        }
        write(fd, files[i].content, strlen(files[i].content));
        fsync(fd);
        close(fd);
        printf("crisp-tag-test: wrote %s = %s\n", files[i].path, files[i].content);
    }
    return 0;
}
