#!/bin/bash
# 冒烟测试：打包后以「测试环境」配置直接启动，验证应用能起来。
#
# 不再切 H2：直接使用打包进 jar 的 application.yml（本机 MySQL mao_sso）。
# 这里只用命令行参数覆盖端口与 issuer（等价于外挂配置的作用），
# 避免与已在运行的 8080 实例冲突，并让发现元数据里的 issuer 与实际端口一致。
set -e

export JAVA_HOME="D:/workspace/java/jdk-25.0.2"
cd D:/workspace/IdeaProjects/mao-app-sso

mvn -q package -DskipTests

exec "$JAVA_HOME/bin/java" -jar target/mao-app-sso-1.0.0.jar \
  --server.port=18080 \
  --sso.issuer-url=http://127.0.0.1:18080
