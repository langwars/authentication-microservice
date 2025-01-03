import { randomUUIDv7 } from "bun";
import { expect, test, describe } from "bun:test";

import * as jose from "jose";

const SERVER_IP_REMOTE = "192.168.1.222";
const SERVER_IP_LOCAL = "127.0.0.1";
const SERVER_PORT = "3000";
const URL = `http://${SERVER_IP_REMOTE}:${SERVER_PORT}`;

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
  let jwt: String;
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
      jwt = body.token;
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
  test("Cleanup", async () => {
    try {
      const url = URL + "/delete";
      const response = await fetch(url, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${jwt}` },
      });
      const body = await response.json();
      expect(body.success).toBe(true);
    } catch (e) {
      expect().fail(`Could not cleanup register endpoint tests: ${e}`);
    }
  });
});

describe("Login Endpoint", () => {
  let jwt: string;
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
  test("POST request to create new user succeeds", async () => {
    try {
      const url = URL + "/register";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({
          email: "test@example.com",
          password: "mypass",
        }),
        headers: { "Content-Type": "application/json" },
      });
      expect(response.status).toEqual(200);
      const body = await response.json();
      expect(body.token).toBeString();
    } catch (e) {
      expect().fail(`Failed to create a new user to test login: ${e}`);
    }
  });
  test("POST request to login with new user credentials succeeds", async () => {
    try {
      const url = URL + "/login";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ email: "test@example.com", password: "mypass" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.token).toBeString();
      jwt = body.token;
    } catch (e) {
      expect().fail(`Failed to login with new user credentials: ${e}`);
    }
  });
  test("POST request to login with correct email / bad pass returns 401", async () => {
    try {
      const url = URL + "/login";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({
          email: "test@example.com",
          password: "mybadpass",
        }),
      });
      expect(response.status).toBe(401);
    } catch (e) {
      expect().fail(`Failed to fail with bad pass: ${e}`);
    }
  });
  test("Cleanup", async () => {
    try {
      const url = URL + "/delete";
      const response = await fetch(url, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${jwt}` },
      });
      const body = await response.json();
      expect(body.success).toBe(true);
    } catch (e) {
      expect().fail(`Could not cleanup register endpoint tests: ${e}`);
    }
  });
});

describe("Delete Endpoint", () => {
  let jwt: string;
  test("GET request returns 404", async () => {
    try {
      const url = URL + "/delete";
      const response = await fetch(url);
      expect(response.status).toEqual(404);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request returns 404", async () => {
    try {
      const url = URL + "/delete";
      const response = await fetch(url, {
        method: "POST",
      });
      expect(response.status).toEqual(404);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("DELETE request without authorization header returns 401", async () => {
    try {
      const url = URL + "/delete";
      const response = await fetch(url, {
        method: "DELETE",
      });
      expect(response.status).toEqual(401);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("DELETE request with bad jwt returns 401", async () => {
    try {
      const url = URL + "/delete";
      const response = await fetch(url, {
        method: "DELETE",
        headers: { Authorization: randomUUIDv7() },
      });
      expect(response.status).toEqual(401);
    } catch (e) {
      expect().fail(`Failed with error: ${e}`);
    }
  });
  test("POST request to create new user succeeds", async () => {
    try {
      const url = URL + "/register";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({
          email: "test@example.com",
          password: "mypass",
        }),
        headers: { "Content-Type": "application/json" },
      });
      expect(response.status).toEqual(200);
      const body = await response.json();
      expect(body.token).toBeString();
      jwt = body.token;
    } catch (e) {
      expect().fail(`Failed to create a new user to test login: ${e}`);
    }
  });
  test("DELETE request with unsigned JWT returns 401", async () => {
    try {
      const url = URL + "/delete";
      const payload = { email: "test@example.com", iat: Date.now() };
      const jwtToken = new jose.UnsecuredJWT(payload).encode();
      const response = await fetch(url, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${jwtToken}` },
      });
      expect(response.status).toBe(401);
    } catch (e) {
      expect().fail(`Failed to send delete request: ${e}`);
    }
  });
  test("Make sure that the user still exists", async () => {
    try {
      const url = URL + "/login";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ email: "test@example.com", password: "mypass" }),
        headers: { "Content-Type": "applicatioin/json" },
      });
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.token).toBeString();
    } catch (e) {
      expect().fail(
        `Trying to make sure that the user still exists failed: ${e}`,
      );
    }
  });
  test("DELETE request with badly signed JWT returns 401", async () => {
    try {
      const url = URL + "/delete";
      const payload = { email: "test@example.com", iat: Date.now() };
      const secret = new TextEncoder().encode(
        "this is a dummy secret that should never pass",
      );
      const jwtToken = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: "HS256" })
        .sign(secret);
      const response = await fetch(url, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${jwtToken}` },
      });
      expect(response.status).toBe(401);
    } catch (e) {
      expect().fail(`Failed to send delete request: ${e}`);
    }
  });
  test("Make sure that the user still exists", async () => {
    try {
      const url = URL + "/login";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ email: "test@example.com", password: "mypass" }),
        headers: { "Content-Type": "applicatioin/json" },
      });
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.token).toBeString();
      jwt = body.token;
    } catch (e) {
      expect().fail(
        `Trying to make sure that the user still exists failed: ${e}`,
      );
    }
  });
  test("DELETE request with proper jwt should delete the user", async () => {
    try {
      const url = URL + "/delete";
      const response = await fetch(url, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${jwt}` },
      });
      const body = await response.json();
      expect(body.success).toBe(true);
    } catch (e) {
      expect().fail(`Could not send delete request: ${e}`);
    }
  });
  test("Make sure that the user was properly deleted", async () => {
    try {
      const url = URL + "/login";
      const response = await fetch(url, {
        method: "POST",
        body: JSON.stringify({ email: "test@example.com", password: "mypass" }),
        headers: { "Content-Type": "applicatioin/json" },
      });
      expect(response.status).toBe(401);
    } catch (e) {
      expect().fail(
        `Trying to make sure that the user does not exist failed: ${e}`,
      );
    }
  });
});
