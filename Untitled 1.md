```
[4:19:54 PM] File change detected. Starting incremental compilation...                                                                                                                                    [4:19:55 PM] Found 0 errors. Watching for file changes.                                                                                                                                                   [Nest] 8473  - 12/15/2025, 4:20:16 PM     LOG [NestFactory] Starting Nest application...             [Nest] 8473  - 12/15/2025, 4:20:16 PM     LOG [InstanceLoader] DatabaseModule dependencies initialized +101ms
[Nest] 8473  - 12/15/2025, 4:20:16 PM     LOG [InstanceLoader] PassportModule dependencies initialized +1ms                                                                                               [Nest] 8473  - 12/15/2025, 4:20:16 PM   ERROR [ExceptionHandler] UnknownDependenciesException [Error]: Nest can't resolve dependencies of the EmailService (?). Please make sure that the argument ConfigService at index [0] is available in the EmailModule context.                                                                                                                                              Potential solutions:
- Is EmailModule a valid NestJS module?                                                              - If ConfigService is a provider, is it part of the current EmailModule?                             - If ConfigService is exported from a separate @Module, is that module imported within EmailModule?
  @Module({                                                                                              imports: [ /* the Module containing ConfigService */ ]                                             })

For more common dependency resolution issues, see: https://docs.nestjs.com/faq/common-errors             at Injector.lookupComponentInParentModules (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/injector.js:286:19)                                                      at async resolveParam (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/injector.js:140:38)
    at async Promise.all (index 0)
    at async Injector.resolveConstructorParams (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/injector.js:169:27)
    at async Injector.loadInstance (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/injector.js:75:13)
    at async Injector.loadProvider (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/injector.js:103:9)
    at async /root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/instance-loader.js:56:13
    at async Promise.all (index 3)
    at async InstanceLoader.createInstancesOfProviders (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/instance-loader.js:55:9)
    at async /root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/instance-loader.js:40:13 {
  type: 'EmailService',
  context: {
    index: 0,
    dependencies: [
      [class ConfigService]
    ],
    name: [class ConfigService]
  },
  metadata: {
    id: '23c472e4c7d4fd5aabbda'
  },
  moduleRef: {
    id: '18244fac9e96677afe36e'
  }
}
```

