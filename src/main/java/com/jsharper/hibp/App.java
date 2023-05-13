package com.jsharper.hibp;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;

public class App {
	private static final Logger logger = LogManager.getLogger();

	public static final String APP_VERSION = "1.0.0";

	public static void main(String[] args) throws IOException {
		String filePath = "pwnedpasswords.txt";
		boolean overwriteExisting = false;
		int numThreads = 8;
		boolean fetchNtlm = false;
		int connTimeoutMs = 500;
		int readTimeoutMs = 1500;

		boolean nextParamFilePath = false;
		boolean nextParamNumThreads = false;
		boolean nextParamConnTimeout = false;
		boolean nextParamReadTimeout = false;
		for (String arg : args) {
			if (nextParamFilePath) {
				filePath = arg;
				nextParamFilePath = false;
			} else if (nextParamNumThreads) {
				numThreads = Integer.parseInt(arg);
				nextParamNumThreads = false;
			} else if (nextParamConnTimeout) {
				connTimeoutMs = Integer.parseInt(arg);
				nextParamConnTimeout = false;
			} else if (nextParamReadTimeout) {
				readTimeoutMs = Integer.parseInt(arg);
				nextParamReadTimeout = false;
			} else {
				if ("-o".equals(arg) || "--overwrite".equals(arg)) {
					overwriteExisting = true;
				} else if ("-n".equals(arg)) {
					fetchNtlm = true;
				} else if ("-p".equals(arg) || "--parallelism".equals(arg)) {
					nextParamNumThreads = true;
				} else if ("-f".equals(arg) || "--filename".equals(arg)) {
					nextParamFilePath = true;
				} else if ("-c".equals(arg) || "--connect-timeout-ms".equals(arg)) {
					nextParamConnTimeout = true;
				} else if ("-r".equals(arg) || "--read-timeout-ms".equals(arg)) {
					nextParamReadTimeout = true;
				} else if ("--trace".equals(arg)) {
					Configurator.setAllLevels(LogManager.getRootLogger().getName(), Level.TRACE);
				} else if ("--version".equals(arg)) {
					logger.info("Version: {}", APP_VERSION);
					return;
				} else if ("--help".equals(arg)) {
					logger.info("Optional parameters:");
					logger.info("-n                                              Fetch NTLM instead of SHA1 hashes");
					logger.info("-p <threadcount> | --parallelism <threadcount>  Set thread count (default: 8)");
					logger.info("-f <filename> | --filename <filename>           Set output filename (default: pwnedpasswords.txt)");
					logger.info("-c <timeout> | --connect-timeout-ms <timeout>   Set connect timeout in milliseconds (default: 500)");
					logger.info("-r <timeout> | --read-timeout-ms <timeout>      Set read timeout in milliseconds (default: 1500)");
					logger.info("--trace                                         Enable trace level debugging");
					logger.info("--version                                       Display app version and exit");
					return;
				} else {
					throw new IllegalArgumentException("Unknown argument " + arg);
				}
			}
		}

		logger.info("HIBP Downloader starting...");

		try {
			long startTime = System.currentTimeMillis();

			new Downloader(filePath, overwriteExisting, numThreads, fetchNtlm, connTimeoutMs, readTimeoutMs).download();

			long elapsedSeconds = (System.currentTimeMillis() - startTime) / 1000;
			long elapsedMinutes = elapsedSeconds / 60;
			elapsedSeconds = elapsedSeconds % 60;
			logger.info("Completed in {}m{}s", elapsedMinutes, elapsedSeconds);
		} catch (FileAlreadyExistsException e) {
			logger.fatal("File [{}] already exists; use -o to overwrite.", filePath);
		}
	}

}
