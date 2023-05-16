package com.jsharper.hibp;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.ServiceUnavailableRetryStrategy;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Downloader {
	private static final Logger logger = LogManager.getLogger();

	private static final int FINAL_RANGE = (1 << (4 * 5)) - 1; // 5 hex digits = 16^5 = 2^20
	private static final String API_BASE_URL = "https://api.pwnedpasswords.com/range/";
	private static final byte[] CRLF = "\r\n".getBytes();

	private static final long INFO_LOG_EVERY_MS = 1000l * 15;
	private static final int MAX_BUFFER_SIZE = 1000;

	private String filePath;
	private boolean overwriteExisting;
	private int numThreads;
	private boolean fetchNtlm;
	private int connTimeoutMs;
	private int readTimeoutMs;

	OutputStream outFile;
	Map<Integer, byte[]> rangeBuffer = new HashMap<>();
	int lastStartedProcessingRange = -1;
	int lastWrittenRange = -1;
	int numActiveThreads = 0;

	public Downloader(String filePath, boolean overwriteExisting, int numThreads, boolean fetchNtlm, int connTimeoutMs, int readTimeoutMs) {
		this.filePath = filePath;
		this.overwriteExisting = overwriteExisting;
		this.numThreads = numThreads;
		this.fetchNtlm = fetchNtlm;
		this.connTimeoutMs = connTimeoutMs;
		this.readTimeoutMs = readTimeoutMs;
	}

	public synchronized void download() throws IOException {
		logger.info("Downloading to [{}] using {} threads...", filePath, numThreads);

		outFile = Files.newOutputStream(Paths.get(filePath), overwriteExisting ? CREATE : CREATE_NEW, TRUNCATE_EXISTING);

		for (int range = 0; range < numThreads && range <= FINAL_RANGE; range++) {
			new Thread(new RangeWorker(range, fetchNtlm)).start();
			numActiveThreads++;
			lastStartedProcessingRange = range;
		}

		boolean done = false;
		long lastInfoLog = 0;

		while (!done) {
			long timeSinceLastInfoLog = System.currentTimeMillis() - lastInfoLog;
			if (timeSinceLastInfoLog > INFO_LOG_EVERY_MS) {
				lastInfoLog += timeSinceLastInfoLog;
				int completed = lastWrittenRange + 1;
				int total = FINAL_RANGE + 1;
				double completedPercentage = completed * 100D / total;
				String completedPercentageStr = String.format("%.2f", completedPercentage);
				logger.info("completed: {}/{} ({}%), active threads: {} buffered ranges: {}", completed, total, completedPercentageStr, numActiveThreads, rangeBuffer.size());
			}
			try {
				long timeUntilNextInfoLog = lastInfoLog + INFO_LOG_EVERY_MS - System.currentTimeMillis();
				if (timeUntilNextInfoLog > 0) {
					wait(timeUntilNextInfoLog);
				}
			} catch (InterruptedException ie) {
				logger.warn("main loop sleep was interrupted!", ie);
				Thread.currentThread().interrupt();
			}

			done = lastWrittenRange == FINAL_RANGE;
		}

		logger.debug("wrote last range; closing file...");
		outFile.close();
	}

	synchronized Integer processRetrievedRangeData(int retrievedRange, byte[] data) throws IOException {
		logger.trace("processRetrievedRangeData({})", retrievedRange);
		int range = retrievedRange;
		if (range == lastWrittenRange + 1) {
			logger.trace("writing range {} after retrieval", range);
			outFile.write(data);
			boolean consumedAnyBuffer = false;
			do {
				lastWrittenRange = range++;
				data = rangeBuffer.remove(range);
				if (data != null) {
					consumedAnyBuffer = true;
					logger.trace("writing range {} from buffer", range);
					outFile.write(data);
				}
			} while (data != null);
			if (consumedAnyBuffer) {
				// wake up anyone who might be waiting for buffer to have room
				notifyAll();
			}
		} else {
			logger.trace("stashing range {} in buffer for later writing", range);
			rangeBuffer.put(range, data);
		}

		Integer nextRange = null;
		if (lastStartedProcessingRange < FINAL_RANGE) {
			if (rangeBuffer.size() >= MAX_BUFFER_SIZE) {
				logger.trace("buffer too full.. let's back off until it has some breathing room...");
				numActiveThreads--;
				do {
					try {
						wait(100);
					} catch (InterruptedException ie) {
						logger.warn("wait-for-buffer-to-shrink loop sleep was interrupted!", ie);
						Thread.currentThread().interrupt();
					}
				} while (rangeBuffer.size() >= MAX_BUFFER_SIZE);
				// we're back in the game! let's re-check to see if there's still work to be done...
				numActiveThreads++;
				if (lastStartedProcessingRange < FINAL_RANGE) {
					logger.trace("buffer has room again; let's get back to work...");
					nextRange = ++lastStartedProcessingRange;
				} else {
					// no more work..
					notifyAll();
				}
			} else {
				nextRange = ++lastStartedProcessingRange;
			}
		} else {
			// no more work..
			notifyAll();
		}
		logger.trace("returning nextRange {}", nextRange);
		return nextRange;
	}



	class RangeWorker implements Runnable {
		private Integer range;
		private boolean fetchNtlm;

		private CloseableHttpClient httpClient;

		RangeWorker(int initialRange, boolean fetchNtlm) {
			this.range = initialRange;
			this.fetchNtlm = fetchNtlm;

			RequestConfig defaultRequestConfig = RequestConfig.custom() 
					.setSocketTimeout(readTimeoutMs)
					.setConnectTimeout(connTimeoutMs)
					.build();

			httpClient = HttpClients.custom()
					.setDefaultRequestConfig(defaultRequestConfig)
					.setRetryHandler(httpRequestRetryHandler)
					.setServiceUnavailableRetryStrategy(serviceUnavailableRetryStrategy)
					.setUserAgent("hibp-downloader-java/" + App.APP_VERSION)
					.build();
		}

		@Override
		public void run() {
			Thread.currentThread().setName("t" + String.format("%03d", range)); // shorten thread name for logging purposes
			try {
				do {
					byte[] data = getRangeData(range);
					range = processRetrievedRangeData(range, data); // returns next range to work, or null if none needed
				} while (range != null);
				logger.trace("thread done; no more new work to do...");
				numActiveThreads--;
			} catch (IOException ioe) {
				//logger.trace("Unrecoverable error while working on range {}!", range, ioe);
				logger.fatal("Unrecoverable error while working on range {}! [{}]/[{}]", range, ioe.getClass().getName(), ioe.getMessage(), ioe);
				System.exit(1);
			}
		}

		byte[] getRangeData(int range) throws IOException {
			byte[] data;
			String rangeHex = String.format("%1$05X", range);
			String url = API_BASE_URL + rangeHex;
			if (fetchNtlm) {
				url += "?mode=ntlm";
			}

			HttpGet httpGet = new HttpGet(url);
			try (CloseableHttpResponse httpResponse = httpClient.execute(httpGet)) { 
				if (httpResponse.getStatusLine().getStatusCode() == 200) {
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					try (BufferedReader reader = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()))) {
						String line;
						while ((line = reader.readLine()) != null) {
							baos.write(rangeHex.getBytes());
							baos.write(line.getBytes());
							baos.write(CRLF);
						}
					}

					data = baos.toByteArray();
				} else {
					// ServiceUnavailableRetryStrategy must have given up retrying non-200 responses
					throw new IOException("Got non-200 response, despite retries! response: [" + httpResponse.getStatusLine().getStatusCode() + "]/[" + httpResponse.getStatusLine().getReasonPhrase() + "]");
				}
			}
			return data;
		}
		private HttpRequestRetryHandler httpRequestRetryHandler = new HttpRequestRetryHandler() {
			private final long WAIT_PERIOD_MS = 2000;
			private final int MAX_RETRIES = 60;

			@Override
			public boolean retryRequest(IOException exception, int executionCount, HttpContext context) {
				boolean ret = executionCount <= MAX_RETRIES;
				if (ret) {
					try {
						Thread.sleep(WAIT_PERIOD_MS);
					} catch (InterruptedException ie) {
						Thread.currentThread().interrupt();
					}
				}
				logger.info("during try #" + executionCount + " caught exception: [" + exception.getClass().getName()+ "] [" + exception.getMessage() + "]; " + (ret ? "retrying" : "giving up!"));
				return ret;
			}
		};

		private ServiceUnavailableRetryStrategy serviceUnavailableRetryStrategy = new ServiceUnavailableRetryStrategy() {
			private final long WAIT_PERIOD_MS = 2000;
			private final int MAX_RETRIES = 60;

			@Override
			public boolean retryRequest(HttpResponse response, int executionCount, HttpContext context) {
				// let's retry non-200 responses for a bit
				boolean ret = executionCount <= MAX_RETRIES && response.getStatusLine().getStatusCode() != 200;
				if (ret) {
					logger.info("during try #" + executionCount + " received [" + response.getStatusLine().getStatusCode() + "]/[" + response.getStatusLine().getReasonPhrase() + "]; retrying");
				}
				return ret;
			}

			@Override
			public long getRetryInterval() {
				return WAIT_PERIOD_MS;
			}
		};

	}
}
