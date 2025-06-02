FROM gradle:8.7-jdk21-jammy AS builder
WORKDIR /app
COPY build.gradle .
COPY settings.gradle .
COPY gradle.properties .
COPY src ./src
RUN gradle build --no-daemon -x test

FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]