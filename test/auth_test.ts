import { randomUUIDv7 } from "bun";
import { expect, test, describe } from "bun:test";

const SERVER_IP_REMOTE = "192.168.1.222";
const SERVER_IP_LOCAL = "127.0.0.1";
const SERVER_PORT = "3000";
const URL = `http://${SERVER_IP_LOCAL}:${SERVER_PORT}`;

describe("Unknown Endpoints", () => {
  test("Server is running", async () => {
    try {
      const response = await fetch(URL);
      expect(response.status).toBeNumber;
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("GET request to random endpoint returns 404", async () => {
    try {
      // In order to prevent "some" cheating in the implementations,
      // we create a random endpoint
      const url = URL + "/" + randomUUIDv7();
      const response = await fetch(url);
      expect(response.status).toEqual(404);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request to random endpoint returns 404", async () => {
    try {
      const url = URL + "/" + randomUUIDv7();
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ message: "Testing bad endpoints (POST)" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(response.status).toEqual(404);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("DELETE request to random endpoint returns 404", async () => {
    try {
      const url = URL + "/" + randomUUIDv7();
      const response = await fetch(url, {
        method: "DELETE",
      });
      expect(response.status).toEqual(404);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
});

describe("Register Endpoint", () => {
  test("GET request returns 404", async () => {
    try {
      const url = URL + "/register";
      const response = await fetch(url);
      expect(response.status).toEqual(404);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("DELETE request returns 404", async () => {
    try {
      const url = URL + "/register";
      const response = await fetch(url, {
        method: "DELETE",
      });
      expect(response.status).toEqual(404);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request without body returns 400", async () => {
    try {
      const url = URL + "/register";
      const response = await fetch(url, {
        method: "POST",
      });
      expect(response.status).toEqual(400);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request without email returns 400", async () => {
    try {
      const url = URL + "/register";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ password: "mypass" }),
        headers: { "Content-Type": "application/json " },
      });
      expect(response.status).toEqual(400);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request without password returns 400", async () => {
    try {
      const url = URL + "/register";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ email: "test@example.com" }),
        headers: { "Content-Type": "application/json " },
      });
      expect(response.status).toEqual(400);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request with bad email returns 400", async () => {
    try {
      const url = URL + "/register";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ email: "test", password: "mypass" }),
        headers: { "Content-Type": "application/json " },
      });
      expect(response.status).toEqual(400);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request with proper credentials returns token", async () => {
    try {
      const url = URL + "/register";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ email: "test@example.com", password: "mypass" }),
        headers: { "Content-Type": "application/json " },
      });
      expect(response.status).toEqual(200);
      const body = await response.json();
      expect(body.token).toBeString();
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request with used credentials returns 400", async () => {
    try {
      const url = URL + "/register";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ email: "test@example.com", password: "mypass" }),
        headers: { "Content-Type": "application/json " },
      });
      expect(response.status).toEqual(400);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
});

describe("Login Endpoint", () => {
  test("GET request returns 404", async () => {
    try {
      const url = URL + "/login";
      const response = await fetch(url);
      expect(response.status).toEqual(404);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("DELETE request returns 404", async () => {
    try {
      const url = URL + "/login";
      const response = await fetch(url, {
        method: "DELETE",
      });
      expect(response.status).toEqual(404);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request without body returns 400", async () => {
    try {
      const url = URL + "/login";
      const response = await fetch(url, {
        method: "POST",
      });
      expect(response.status).toEqual(400);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request without email returns 400", async () => {
    try {
      const url = URL + "/login";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ password: "mypass" }),
        headers: { "Content-Type": "application/json " },
      });
      expect(response.status).toEqual(400);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request without password returns 400", async () => {
    try {
      const url = URL + "/login";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ email: "test@example.com" }),
        headers: { "Content-Type": "application/json " },
      });
      expect(response.status).toEqual(400);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request with bad email returns 400", async () => {
    try {
      const url = URL + "/login";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ email: "test", password: "mypass" }),
        headers: { "Content-Type": "application/json " },
      });
      expect(response.status).toEqual(400);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
});
