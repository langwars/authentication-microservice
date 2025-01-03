declare var self: Worker;

const SERVER_IP_REMOTE = "192.168.1.222";
const SERVER_IP_LOCAL = "127.0.0.1";
const SERVER_PORT = "3000";
const URL = `http://${SERVER_IP_REMOTE}:${SERVER_PORT}`;

interface RequestStats {
  status: number;
  success: boolean;
}

interface LoginStats {
  successful: number;
  failed: number;
}

interface WorkerStats {
  register: RequestStats;
  logins: LoginStats;
  delete: RequestStats;
}

async function sendRequests(currentIndex: number): Promise<WorkerStats> {
  return new Promise(async (resolve, reject) => {
    let stats: WorkerStats = {
      register: { status: 0, success: false },
      logins: { successful: 0, failed: 0 },
      delete: { status: 0, success: false },
    };

    // Send a Register Request - expecting 200
    const response = await fetch(`${URL}/register`, {
      method: "POST",
      body: JSON.stringify({
        email: `user${currentIndex}@example.com`,
        password: "password",
      }),
      headers: {
        "Content-Type": "application/json",
      },
    });
    stats.register.status = response.status;
    stats.register.success = response.status === 200;
    const body = await response.json();

    // Create promises for login requests with different scenarios
    const loginPromises = new Array(1600);

    // 1000 successful login requests - expecting 200
    for (let i = 0; i < 2000; i++) {
      loginPromises[i] = fetch(`${URL}/login`, {
        method: "POST",
        body: JSON.stringify({
          email: `user${currentIndex}@example.com`,
          password: "password",
        }),
        headers: {
          "Content-Type": "application/json",
        },
      });
    }

    // Wait for all login requests to complete
    const loginResults = await Promise.allSettled(loginPromises);
    for (const result of loginResults) {
      if (result.status === "fulfilled") {
        const status = result.value.status;
        if (status === 200) {
          stats.logins.successful++;
        } else {
          stats.logins.failed++;
        }
      } else {
        stats.logins.failed++;
      }
    }

    // Send a delete request - expecting 200
    const deleteResponse = await fetch(`${URL}/delete`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${body.token}`,
      },
    });
    stats.delete.status = deleteResponse.status;
    stats.delete.success = deleteResponse.status === 200;

    resolve(stats);
  });
}

self.onmessage = (event: MessageEvent) => {
  const currentIndex: number = event.data;
  sendRequests(currentIndex).then((stats) => {
    self.postMessage(stats);
  });
};
