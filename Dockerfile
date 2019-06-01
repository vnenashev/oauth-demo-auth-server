#
# Build stage
#
FROM maven:3.6.1-jdk-8-slim AS build
COPY pom.xml /app/
RUN mvn -f /app/pom.xml dependency:go-offline
COPY src /app/src
RUN mvn -f /app/pom.xml clean package -Dmaven.test.skip

#
# Package stage
#
FROM openjdk:8-jre-slim
COPY --from=build /app/target/oauth-demo-auth-server.jar /usr/local/lib/oauth-demo-auth-server.jar
EXPOSE 8081
ENTRYPOINT ["java","-jar","/usr/local/lib/oauth-demo-auth-server.jar"]
