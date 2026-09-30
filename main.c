#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/elf64.h>
#include <sys/stat.h>
#ifdef DUMP_GAME
#include <sys/param.h>
#include <sys/mount.h>
#endif

#include "selfpager.h"

static void mkdirs(const char *dir) {
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0777);
            *p = '/';
        }
    mkdir(tmp, 0777);
}

static int is_usb_mounted(int index) {
    char path[64];
    snprintf(path, sizeof(path), "/mnt/usb%d", index);
    struct stat parent_stat;
    if (stat("/mnt", &parent_stat) != 0) {
        return 0;
    }
    struct stat usb_stat;
    if (stat(path, &usb_stat) != 0) {
        return 0;
    }
    return (parent_stat.st_dev != usb_stat.st_dev);
}

int decrypt_self_by_path(const char *input_file_path, const char *output_file_path, int *num_success, int *num_failed) {
    int input_file_fd = open(input_file_path, O_RDONLY);
    if (input_file_fd < 0) {
        puts("Failed to open input file");
        if (num_failed) (*num_failed)++;
        return -1;
    }

    uint64_t output_file_size = 0;
    char *out_data = NULL;
    int res = decrypt_self(input_file_fd, &out_data, &output_file_size);
    close(input_file_fd);
    if (res == DECRYPT_ERROR_INPUT_NOT_SELF) {
        return res;
    } else if (res != 0 && res != DECRYPT_SUCCESS_PLAINTEXT_SELF) {
        printf("Failed to decrypt self: %s , error %d\n", input_file_path, res);
        if (num_failed) (*num_failed)++;
        return res;
    }

    char *last_slash = strrchr(output_file_path, '/');
    if (last_slash) {
        char output_dir_path[PATH_MAX];
        long dir_path_len = last_slash - output_file_path;
        strncpy(output_dir_path, output_file_path, dir_path_len);
        output_dir_path[dir_path_len] = '\0';
        mkdirs(output_dir_path);
    }
    int output_file_fd = open(output_file_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (output_file_fd < 0) {
        puts("Failed to open output file");
        munmap(out_data, output_file_size);
        unlink(output_file_path);
        if (num_failed) (*num_failed)++;
        return -1;
    }
    ssize_t write_res = write(output_file_fd, out_data, output_file_size);
    munmap(out_data, output_file_size);
    close(output_file_fd);
    if (write_res != output_file_size) {
        puts("Failed to write complete output file");
        unlink(output_file_path);
        if (num_failed) (*num_failed)++;
        return -1;
    }
    printf("%s: '%s' -> '%s'\n",
           res == DECRYPT_SUCCESS_PLAINTEXT_SELF ? "Unwrapped plaintext self" : "Decrypted self",
           input_file_path, output_file_path);

    if (num_success) (*num_success)++;
    return res;
}

static const char *allowed_exts[] = {".elf", ".self", ".prx", ".sprx", ".bin"};
static const int allowed_exts_count = sizeof(allowed_exts) / sizeof(allowed_exts[0]);

static int decrypt_all_selfs_in_directory(const char *input_dir_path, const char *output_dir_path, int recursive, int *num_success, int *num_failed) {
    if (!input_dir_path || !output_dir_path) {
        return -1;
    }

    DIR *dir = opendir(input_dir_path);
    if (!dir) {
        perror("Failed to open input directory");
        return -1;
    }

    struct dirent *entry;
    char inpath[PATH_MAX];
    char outpath[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }

        int path_len = snprintf(inpath, sizeof(inpath), "%s/%s", input_dir_path, name);
        if (path_len < 0 || (size_t)path_len >= sizeof(inpath)) {
            printf("Skipping input path that is too long: %s/%s\n", input_dir_path, name);
            continue;
        }
        path_len = snprintf(outpath, sizeof(outpath), "%s/%s", output_dir_path, name);
        if (path_len < 0 || (size_t)path_len >= sizeof(outpath)) {
            printf("Skipping output path that is too long: %s/%s\n", output_dir_path, name);
            continue;
        }

        unsigned char entry_type = entry->d_type;
        if (entry_type == DT_UNKNOWN) {
            struct stat st;
            // Do not follow symlinks: keep the same scope as known d_type entries.
            if (lstat(inpath, &st) != 0) {
                printf("Failed to determine entry type: %s: %s\n", inpath, strerror(errno));
                continue;
            }
            if (S_ISDIR(st.st_mode)) entry_type = DT_DIR;
            else if (S_ISREG(st.st_mode)) entry_type = DT_REG;
        }

        if (entry_type == DT_DIR && recursive) {
            // if the input dir starts with "/mnt/sandbox/pfsmnt" skip entry if ends with "-app0-patch0-union",
            // we only care about app0 and patch0
            if (entry->d_namlen == sizeof("PPSA00000-app0-patch0-union") - 1 &&
                strncmp(input_dir_path, "/mnt/sandbox/pfsmnt", sizeof("/mnt/sandbox/pfsmnt") - 1) == 0 &&
                strncmp(name + 9, "-app0-patch0-union", sizeof("-app0-patch0-union") - 1) == 0) {
                continue;
            }

            decrypt_all_selfs_in_directory(inpath, outpath, recursive, num_success, num_failed);
        } else if (entry_type == DT_REG) {
            int has_allowed_ext = 0;
            const char *ext = strrchr(name, '.');
            for (int i = 0; i < allowed_exts_count; i++) {
                if (ext && strcasecmp(ext, allowed_exts[i]) == 0) {
                    has_allowed_ext = 1;
                    break;
                }
            }
            if (!has_allowed_ext) {
                continue;
            }

            decrypt_self_by_path(inpath, outpath, num_success, num_failed);
        }
    }

    closedir(dir);
    return 0;
}

#ifdef DUMP_GAME
static void decrypt_shadowmount_games(const char *output_base_path, int *num_success, int *num_failed) {
    // ShadowMountPlus mounts its game sources here using nullfs, optionally
    // with a unionfs backport overlay. Do not scan unmounted title directories
    // or raw image/container mounts, which can duplicate the same game.
    const char *root = "/system_ex/app";
    DIR *dir = opendir(root);
    if (!dir) {
        printf("Cannot scan ShadowMount game mounts: %s: %s\n", root, strerror(errno));
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;

        char inpath[PATH_MAX], outpath[PATH_MAX];
        int len = snprintf(inpath, sizeof(inpath), "%s/%s", root, name);
        if (len < 0 || (size_t)len >= sizeof(inpath)) continue;
        struct stat st;
        if (lstat(inpath, &st) != 0) {
            printf("Failed to inspect title directory: %s: %s\n", inpath, strerror(errno));
            continue;
        }
        if (!S_ISDIR(st.st_mode)) continue;
        struct statfs fs;
        if (statfs(inpath, &fs) != 0) {
            printf("Failed to inspect game mount: %s: %s\n", inpath, strerror(errno));
            continue;
        }
        if (strcmp(fs.f_mntonname, inpath) != 0 ||
            (strcmp(fs.f_fstypename, "nullfs") != 0 &&
             strcmp(fs.f_fstypename, "unionfs") != 0)) continue;

        len = snprintf(outpath, sizeof(outpath), "%s%s", output_base_path, inpath);
        if (len < 0 || (size_t)len >= sizeof(outpath)) continue;
        printf("Scanning mounted game: %s (%s)\n", inpath, fs.f_fstypename);
        decrypt_all_selfs_in_directory(inpath, outpath, 1, num_success, num_failed);
    }
    closedir(dir);
}
#endif

int main() {
    int num_success = 0;
    int num_failed = 0;
    char output_path[PATH_MAX];
    const char *output_base_path = is_usb_mounted(0) ? "/mnt/usb0/dump" : "/data/dump";
    printf("Output base path: %s\n", output_base_path);

#ifdef DUMP_SYSTEM_COMMON_LIB
    snprintf(output_path, sizeof(output_path), "%s/system/common/lib", output_base_path);
    decrypt_all_selfs_in_directory("/system/common/lib", output_path, 0, &num_success, &num_failed);
#endif

#ifdef DUMP_FULL_SYSTEM
    snprintf(output_path, sizeof(output_path), "%s/system", output_base_path);
    decrypt_all_selfs_in_directory("/system", output_path, 1, &num_success, &num_failed);
    snprintf(output_path, sizeof(output_path), "%s/system_ex", output_base_path);
    decrypt_all_selfs_in_directory("/system_ex", output_path, 1, &num_success, &num_failed);
#endif

#ifdef DUMP_SHELLCORE
    snprintf(output_path, sizeof(output_path), "%s/system/vsh/SceShellCore.elf", output_base_path);
    decrypt_self_by_path("/system/vsh/SceShellCore.elf", output_path, &num_success, &num_failed);
#endif

#ifdef DUMP_GAME
    snprintf(output_path, sizeof(output_path), "%s/mnt/sandbox/pfsmnt", output_base_path);
    decrypt_all_selfs_in_directory("/mnt/sandbox/pfsmnt", output_path, 1, &num_success, &num_failed);
    decrypt_shadowmount_games(output_base_path, &num_success, &num_failed);
#endif

    printf("Done. Success: %d, Failed: %d\n", num_success, num_failed);
    return 0;
}
