interface StatsCounter {
  successful: number;
  failed: number;
}

interface Stats {
  register: StatsCounter;
  logins: StatsCounter;
  delete: StatsCounter;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
}

interface WorkerStats {
  register: { success: boolean; status: number };
  logins: { successful: number; failed: number };
  delete: { success: boolean; status: number };
}

const WORKER_COUNT = 100;
let activeWorkers = WORKER_COUNT;

const stats: Stats = {
  register: { successful: 0, failed: 0 },
  logins: { successful: 0, failed: 0 },
  delete: { successful: 0, failed: 0 },
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
};

let start = performance.now();
console.log("Starting to create workers...");
for (let i = 0; i < WORKER_COUNT; i++) {
  const currentWorker = new Worker(
    new URL("./auth_bench_worker.ts", import.meta.url),
  );
  currentWorker.addEventListener("open", () => {
    currentWorker.postMessage(i);
  });
  currentWorker.addEventListener("error", (error) => {
    activeWorkers--;
  });
  currentWorker.onmessage = (event) => {
    const workerStats: WorkerStats = event.data;

    // Update register stats
    if (workerStats.register.success) stats.register.successful++;
    else stats.register.failed++;

    // Update login stats
    stats.logins.successful += workerStats.logins.successful;
    stats.logins.failed += workerStats.logins.failed;

    // Update delete stats
    if (workerStats.delete.success) stats.delete.successful++;
    else stats.delete.failed++;

    activeWorkers--;

    if (activeWorkers === 0) {
      const totalTime = (performance.now() - start) / 1000;

      // Total Requests
      stats.totalRequests = stats.register.successful + stats.register.failed;
      stats.totalRequests += stats.logins.successful + stats.logins.failed;
      stats.totalRequests += stats.delete.successful + stats.delete.failed;

      // Successful Requests
      stats.successfulRequests =
        stats.register.successful +
        stats.logins.successful +
        stats.delete.successful;

      // Errored Requests
      stats.failedRequests =
        stats.register.failed + stats.logins.failed + stats.delete.failed;

      // Error Percentage
      const errorPercentage =
        (stats.failedRequests / stats.totalRequests) * 100;

      // Throughput of total requests
      const requestsPerSecond = stats.totalRequests / totalTime;
      // Throughput of successful requests
      const successfulRequestsPerSecond = stats.successfulRequests / totalTime;
      // Throughput of errored requests
      const failedRequestsPerSecond = stats.failedRequests / totalTime;

      console.log("\n=== Final Statistics ===");
      console.log(`Total time: ${totalTime.toFixed(2)} seconds`);
      console.log(`Total requests: ${stats.totalRequests}`);
      console.log(`Successful requests: ${stats.successfulRequests}`);
      console.log(`Failed requests: ${stats.failedRequests}`);
      console.log(`Error Percentage: ${errorPercentage.toFixed(2)}%`);
      console.log(`Requests per second: ${requestsPerSecond.toFixed(2)}`);
      console.log(
        `Successful requests per second: ${successfulRequestsPerSecond.toFixed(2)}`,
      );
      console.log(
        `Errored requests per second: ${failedRequestsPerSecond.toFixed(2)}`,
      );

      console.log("\nRegister Requests:");
      console.log(`  Successful: ${stats.register.successful}`);
      console.log(`  Failed: ${stats.register.failed}`);

      console.log("\nLogin Requests:");
      console.log(`  Successful: ${stats.logins.successful}`);
      console.log(`  Failed: ${stats.logins.failed}`);

      console.log("\nDelete Requests:");
      console.log(`  Successful: ${stats.delete.successful}`);
      console.log(`  Failed: ${stats.delete.failed}`);
    }

    currentWorker.terminate();
  };
}
