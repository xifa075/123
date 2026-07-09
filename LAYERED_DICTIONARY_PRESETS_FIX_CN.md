# 分层字典内置预设修复说明

## 背景

上一版只提供了外部 `CGN-layered-dictionary-groups.zip` 示例包，插件本体首次打开“配置中心 → 分层字典”时仍只显示“默认旧字典（兼容）”。这会让用户误以为内置字典组没有生效。

## 本次修复

- 新增 `burp.dictionary.PresetLayeredDictionaryGroups`。
- 首次运行且没有任何自定义分层字典配置时，自动物化 12 个内置预设字典组。
- 如果旧版平铺字典中已有内容，会额外生成“默认旧字典（兼容迁移）”组，旧配置本身不被覆盖。
- 如果用户已经存在自定义分层字典配置，则不会自动写入预设组，避免覆盖团队已有配置。
- 预设组写入 `cgn_layered_dictionaries.properties` 后可直接增删改、导入导出。

## 内置预设组

1. 根目录入口
2. API 二/三级接口
3. Spring Actuator
4. Swagger / OpenAPI 文档
5. 敏感配置文件
6. 前端配置与 JS 资产
7. 备份与压缩包
8. 后台与认证入口
9. DevOps / CI 管理面板
10. 云原生 / Kubernetes / Well-known
11. Java 框架专项
12. PHP / Node / Python 框架专项

## 注意

若本机已经生成过 `cgn_layered_dictionaries.properties` 且其中已有自定义组，插件不会覆盖它。想重新生成内置预设，可以备份并删除该文件后重新加载插件。
