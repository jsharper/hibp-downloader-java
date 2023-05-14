# hibp-downloader-java
Have I Been Pwned (HIBP) Password Hash Downloader (Java)

An alternate (to <https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader>) downloader for HIBP Pwned Password hashes that does not require Windows or .NET.

See <https://haveibeenpwned.com/Passwords>

# Example usage in Docker:

```
docker run -it --rm -v $(pwd):/out jsharper/hibp-downloader -f hibp-hashes.txt -p 64
```


# To build:

`git clone https://github.com/jsharper/hibp-downloader-java.git`

`docker run -t --rm -v $(pwd)/hibp-downloader-java:/build maven mvn -f /build/pom.xml package`

`docker build -t hibp-downloader hibp-downloader-java`
