#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>

typedef struct {
    char *name;
    int is_dir;
} FileEntry;

// Simple JSON string escape
void print_escaped_json(const char *str) {
    putchar('"');
    while (*str) {
        if (*str == '"') printf("\\\"");
        else if (*str == '\\') printf("\\\\");
        else if (*str == '\b') printf("\\b");
        else if (*str == '\f') printf("\\f");
        else if (*str == '\n') printf("\\n");
        else if (*str == '\r') printf("\\r");
        else if (*str == '\t') printf("\\t");
        else if ((unsigned char)*str < 32) printf("\\u%04x", *str);
        else putchar(*str);
        str++;
    }
    putchar('"');
}

// Format size
void format_size(long size, char *out) {
    const char *units[] = {"B", "K", "M", "G", "T", "P"};
    int i = 0;
    double s = size;
    if (size == 0) {
        strcpy(out, "0B");
        return;
    }
    while (s >= 1024 && i < 5) {
        s /= 1024;
        i++;
    }
    if (i == 0) sprintf(out, "%ld%s", size, units[i]);
    else sprintf(out, "%.2f%s", s, units[i]);
}

int compare_entries(const void *a, const void *b) {
    FileEntry *fa = (FileEntry *)a;
    FileEntry *fb = (FileEntry *)b;
    if (fa->is_dir != fb->is_dir) {
        return fb->is_dir - fa->is_dir; // Dirs first
    }
    return strcasecmp(fa->name, fb->name);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("{\"error\": \"Usage: %s <path> <page> <per_page>\"}\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    int page = atoi(argv[2]);
    int per_page = atoi(argv[3]);
    if (page < 1) page = 1;
    if (per_page < 1) per_page = 50;

    DIR *d;
    struct dirent *dir;
    d = opendir(path);
    if (!d) {
        printf("{\"error\": \"Could not open directory\"}\n");
        return 1;
    }

    // Dynamic array
    int capacity = 1000;
    int count = 0;
    FileEntry *entries = malloc(capacity * sizeof(FileEntry));

    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;

        if (count >= capacity) {
            capacity *= 2;
            entries = realloc(entries, capacity * sizeof(FileEntry));
        }
        
        entries[count].name = strdup(dir->d_name);
        entries[count].is_dir = (dir->d_type == DT_DIR); 
        // Note: d_type might be DT_UNKNOWN on some FS, need fallback?
        // Let's assume stat will fix it later if needed, but for sort we guess
        // If unknown, treat as file for sort, specific check later
        
        count++;
    }
    closedir(d);

    // Sort
    qsort(entries, count, sizeof(FileEntry), compare_entries);

    // Pagination
    int start = (page - 1) * per_page;
    int end = start + per_page;
    int has_more = (end < count) ? 1 : 0;
    if (end > count) end = count;

    // Output JSON
    printf("{\n");
    printf("  \"current_path\": "); print_escaped_json(path); printf(",\n");
    printf("  \"page\": %d,\n", page);
    printf("  \"total\": %d,\n", count);
    printf("  \"has_more\": %s,\n", has_more ? "true" : "false");
    printf("  \"items\": [\n");

    char clean_path[4096];
    
    // Remove trailing slash for path construction
    int path_len = strlen(path);
    strcpy(clean_path, path);
    if (path_len > 1 && clean_path[path_len-1] == '/') {
        clean_path[path_len-1] = '\0';
    }

    struct stat st;
    char fullpath[4096];
    char timebuf[64];
    char sizebuf[32];
    char permbuf[16];

    for (int i = start; i < end; i++) {
        if (i > start) printf(",\n");
        
        snprintf(fullpath, sizeof(fullpath), "%s/%s", clean_path, entries[i].name);
        
        int is_dir = entries[i].is_dir;
        long size = 0;
        *timebuf = '\0';
        int uid = 0, gid = 0;
        mode_t mode = 0;

        if (stat(fullpath, &st) == 0) {
            is_dir = S_ISDIR(st.st_mode);
            size = st.st_size;
            struct tm *tm = localtime(&st.st_mtime);
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
            uid = st.st_uid;
            gid = st.st_gid;
            mode = st.st_mode;
        } else {
             strcpy(timebuf, "-");
        }

        // Build permission string like "rwxr-xr-x"
        snprintf(permbuf, sizeof(permbuf), "%c%c%c%c%c%c%c%c%c",
            (mode & S_IRUSR) ? 'r' : '-',
            (mode & S_IWUSR) ? 'w' : '-',
            (mode & S_IXUSR) ? 'x' : '-',
            (mode & S_IRGRP) ? 'r' : '-',
            (mode & S_IWGRP) ? 'w' : '-',
            (mode & S_IXGRP) ? 'x' : '-',
            (mode & S_IROTH) ? 'r' : '-',
            (mode & S_IWOTH) ? 'w' : '-',
            (mode & S_IXOTH) ? 'x' : '-'
        );

        format_size(size, sizebuf);

        printf("    {\n");
        printf("      \"name\": "); print_escaped_json(entries[i].name); printf(",\n");
        printf("      \"path\": "); print_escaped_json(fullpath); printf(",\n");
        printf("      \"is_dir\": %s,\n", is_dir ? "true" : "false");
        printf("      \"size\": \"%s\",\n", is_dir ? "-" : sizebuf);
        printf("      \"date\": \"%s\",\n", timebuf);
        printf("      \"perm\": \"%s\",\n", permbuf);
        printf("      \"uid\": %d,\n", uid);
        printf("      \"gid\": %d\n", gid);
        printf("    }");
    }

    printf("\n  ]\n");
    printf("}\n");

    // Clean up
    for (int i = 0; i < count; i++) {
        free(entries[i].name);
    }
    free(entries);

    return 0;
}
