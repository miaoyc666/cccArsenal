/*
File name    : demo.c
Author       : miaoyc
Create Date  : 2023/8/16 14:20
Update Date  : 2023/8/16 14:20
Description  :
*/

#include <stdio.h>
#include <stdlib.h>
#include <yaml.h>

typedef struct {
    char* apikey;
} Config;


Config globalConfig;

Config* loadYaml(char* configFilePath) {
    memset(&globalConfig, 0, sizeof(Config));
    // 打开YAML文件
    FILE* file = fopen(configFilePath, "r");
    if (file == NULL) {
        printf("无法打开YAML文件\n");
        return NULL;
    }

    // 初始化libyaml解析器
    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) {
        printf("无法初始化解析器\n");
        fclose(file);
        return NULL;
    }

    // 设置输入文件流
    yaml_parser_set_input_file(&parser, file);

    // 解析YAML文档
    int done = 0;
    yaml_event_t event;
    char* apikey = NULL;
    while (!done) {
        if (!yaml_parser_parse(&parser, &event)) {
            printf("解析失败\n");
            break;
        }

        switch (event.type) {
            case YAML_SCALAR_EVENT:
                if (strcmp((char*)event.data.scalar.value, "apikey") == 0) {
                    yaml_parser_parse(&parser, &event);
                    globalConfig.apikey = strdup((char*)event.data.scalar.value);
                }
                break;

            case YAML_STREAM_END_EVENT:
                done = 1;
                break;

            default:
                break;
        }

        yaml_event_delete(&event);
    }

    // 清理解析器
    yaml_parser_delete(&parser);

    // 关闭文件
    fclose(file);

    // 释放分配的内存
    free(apikey);

    return &globalConfig;
}

int main() {
    char* configFilePath = "config.yaml";
    Config* config = loadYaml(configFilePath);
    printf("%s\n", config->apikey);
}
