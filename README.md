# hibp-downloader-java
Have I Been Pwned (HIBP) Password Hash Downloader (Java)

An alternate to <https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader> that does not require Windows or .NET.

See <https://haveibeenpwned.com/Passwords>


# Example usage in Docker:

```
docker run -it --rm -v $(pwd):/out jsharper/hibp-downloader -f hibp-hashes.txt -p 96
```


# Supported Parameters:

```
-n | --ntlm-hashes                              Fetch NTLM instead of SHA1 hashes
-p <threadcount> | --parallelism <threadcount>  Set thread count (default: 64)
-f <filename> | --filename <filename>           Set output filename (default: pwnedpasswords.txt)
-o | --overwrite                                Overwrite output file if it already exists
-c <timeout> | --connect-timeout-ms <timeout>   Set connect timeout in milliseconds (default: 500)
-r <timeout> | --read-timeout-ms <timeout>      Set read timeout in milliseconds (default: 2000)
--trace                                         Enable trace level debugging
--version                                       Display app version and exit
--help                                          Display help info
```


# To build:

`git clone https://github.com/jsharper/hibp-downloader-java.git`

`docker run -t --rm -v $(pwd)/hibp-downloader-java:/build maven mvn -f /build/pom.xml package`

`docker build -t hibp-downloader hibp-downloader-java`
