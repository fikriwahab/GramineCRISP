#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(void) {
    printf("=== Protected Files Demo ===\n\n");

    /* Write to encrypted file (Protected File) */
    const char* secret = "INI DATA RAHASIA: password=SuperSecret123!";
    printf("[1] Menulis ke /encrypted/secret.txt: \"%s\"\n", secret);

    int fd = open("/encrypted/secret.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("ERROR: open encrypted file failed\n");
        return 1;
    }
    write(fd, secret, strlen(secret));
    fsync(fd);
    close(fd);
    printf("[2] File encrypted ditulis + fsync + close.\n\n");

    /* Write to normal file (NOT encrypted) */
    const char* normal = "INI DATA BIASA: hello world";
    printf("[3] Menulis ke /plain/normal.txt: \"%s\"\n", normal);

    int fd2 = open("/plain/normal.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd2 < 0) {
        printf("ERROR: open normal file failed\n");
        return 1;
    }
    write(fd2, normal, strlen(normal));
    fsync(fd2);
    close(fd2);
    printf("[4] File biasa ditulis + fsync + close.\n\n");

    /* Read back encrypted file to prove Gramine decrypts transparently */
    printf("[5] Baca balik /encrypted/secret.txt dari dalam Gramine:\n");
    int fd3 = open("/encrypted/secret.txt", O_RDONLY);
    if (fd3 < 0) {
        printf("ERROR: open for read failed\n");
        return 1;
    }
    char buf[256] = {0};
    int n = read(fd3, buf, sizeof(buf) - 1);
    close(fd3);
    printf("    Isi: \"%s\" (%d bytes)\n\n", buf, n);

    printf("[6] Sekarang coba buka file dari LUAR Gramine:\n");
    printf("    $ xxd encrypted_dir/secret.txt | head\n");
    printf("    Harusnya ciphertext (nggak bisa dibaca)!\n\n");

    printf("    $ cat plain_dir/normal.txt\n");
    printf("    Harusnya plaintext (bisa dibaca)!\n\n");

    printf("=== Demo selesai ===\n");
    return 0;
}
