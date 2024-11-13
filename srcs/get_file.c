#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INITIAL_CAPACITY 10

char    **get_file(char *path) {
    size_t i = 0;
    size_t n = 0;
    size_t size = 0;
    char *buffer = NULL;
    FILE *fptr = NULL;
    char **tab = NULL;
    size_t max = INITIAL_CAPACITY;

    if ((fptr = fopen(path, "r")) != NULL) {
        if ((tab = (char**)malloc(sizeof(char*)*(max + 1))) != NULL) {
            while (getline(&buffer, &n, fptr) != -1) {
                size = strlen(buffer);
                if (buffer[size - 1] == '\n') {
                    buffer[size - 1] = '\0';
                }
                if (i > max) {
                    max *= 2;
                    char **tmp = (char**)realloc(tab, sizeof(char*)*(max+1));
                    if (tmp != NULL) {
                        tab = tmp;
                    }
                }
                if ((tab[i] = malloc(sizeof(char)*(size+1))) != NULL)
                    strcpy(tab[i], buffer);
                i++;
            }
            tab[i] = NULL;
        }
    }
    free(buffer);
    fclose(fptr);
    return (tab);
}
