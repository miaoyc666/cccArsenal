/*
File name    : download.c
Author       : miaoyc
Create Date  : 2023/8/2 15:25
Update Date  : 2023/8/2 15:25
Description  :
*/

#include <stdio.h>
#include <curl/curl.h>

// 回调函数写入文件
size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    FILE* file = (FILE*)userp;
    return fwrite(contents, size, nmemb, file);
}

int main() {
    CURL* curl;
    FILE* file;
    CURLcode res;

    // 初始化libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // 创建curl句柄
    curl = curl_easy_init();
    if (!curl) {
        printf("无法初始化libcurl。\n");
        return 1;
    }

    // 打开要下载的文件
    file = fopen("downloaded_file.txt", "wb");
    if (!file) {
        printf("无法创建下载文件。\n");
        curl_easy_cleanup(curl);
        return 1;
    }

    // 设置URL和回调函数
    curl_easy_setopt(curl, CURLOPT_URL, "https://xx.xx.com/xxxx.enc");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);

    // 执行下载操作
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("下载失败：%s\n", curl_easy_strerror(res));
    } else {
        printf("文件下载完成。\n");
    }

    // 关闭文件指针
    fclose(file);

    // 清理curl句柄和全局资源
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}