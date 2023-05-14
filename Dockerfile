FROM amazoncorretto:17

COPY target/hibp-downloader.jar /hibp-downloader.jar

WORKDIR /out

ENTRYPOINT ["java", "-jar", "/hibp-downloader.jar"]
