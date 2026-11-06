#!/bin/bash
# 冒烟测试：打包后启动，将 H2 加入 loader.path 替代 MySQL
set -e
export JAVA_HOME="D:/workspace/java/jdk-25.0.2"
export SSO_DATASOURCE_URL="jdbc:h2:mem:smoke;MODE=MySQL;DB_CLOSE_DELAY=-1"
export SSO_DATASOURCE_USERNAME="sa"
export SSO_DATASOURCE_PASSWORD=""
export SSO_ADMIN_PASSWORD="smoke-admin-pass"
export SSO_CLIENT_SECRET="smoke-client-secret"
export SSO_ISSUER_URL="http://localhost:8080"
cd D:/workspace/IdeaProjects/mao-app-sso
mvn -q package -DskipTests
H2_JAR=$(find "$HOME/.m2/repository/com/h2database/h2/2.4.240" -name "h2-*.jar" | head -1)
echo "H2_JAR=$H2_JAR"
exec "$JAVA_HOME/bin/java" -Dloader.main=com.mao.sso.App -Dloader.path="$H2_JAR" \
  -cp target/mao-app-sso-1.0.0.jar \
  org.springframework.boot.loader.launch.PropertiesLauncher \
  --spring.datasource.driver-class-name=org.h2.Driver \
  --server.port=18080
