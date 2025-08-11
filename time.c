#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        perror("time");
        return 1;
    }

    // Thread-safe UTC time
    struct tm utc_tm;
    if (gmtime_r(&now, &utc_tm) == NULL) {
        perror("gmtime_r");
        return 1;
    }
    printf("UTC time:    %s", asctime(&utc_tm));

    // Thread-safe local time
    struct tm local_tm;
    if (localtime_r(&now, &local_tm) == NULL) {
        perror("localtime_r");
        return 1;
    }
    printf("Local time:  %s", asctime(&local_tm));

    // Show TZ variable
    char *tz = getenv("TZ");
    printf("TZ:          %s\n", tz ? tz : "(not set)");

    return 0;
}

