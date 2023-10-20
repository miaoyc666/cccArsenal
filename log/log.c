#include <stdio.h>
#include <time.h>

void logMessage(const char* message) {
    time_t now = time(NULL);
    struct tm* timeinfo = localtime(&now);

    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    printf("[%s] [LOG] %s\n", timestamp, message);
}

int main() {
    logMessage("This is a log message with timestamp");
    return 0;
}