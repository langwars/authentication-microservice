# SUBMISSION GUIDELINES

## Introduction

This is the place for people who want to submit their authentication microservice to be benchmarked against other users' submissions in different languages. 

The prompt for the AI was too generic/open-ended so that it doesn't get stuck in implementation details that it does not know how to solve. However, for user submissions, we have some more strict rules to kind of level the playing field, but in the spirit of the LLM challenge.

## Rules

1. You support 3 endpoints: `/register`, `/login`, and `/delete`. Register and Login are POST requests, Delete is a DELETE request (you can see how the endpoints are called in the Apache Jmeter file).
2. You can use any language that you want (as long as I can run it in my MacBook) and any framework or library that you want (as long as you provide instructions on how to run your code; for specialized libraries).
3. The storage of the users is in-memory (not persistent) and you store email and a hashed version of the password.
4. You return a JWT on successful register/login, which includes the user email which you can verify before allowing delete.
5. The algorithms that are allowed for JWT signing are HS256 and RS256 and the algorithms that are allowed for password hashing are SHA-256 and SHA-512.

## Submission Format

You clone this repository and add your code in a directory named after your github username. Then, you submit a pull request.

For example, let's say that you want to submit a Rust and a Zig implementation and your github username is `deeznats`. 

After you have cloned this repo, you create a new directory called `deeznats` in the `submissions/rust` directory and add your Rust code there along with any potential instructions on how to build it. 

You also create a new directory called `deeznats` in the `submissions/zig` directory and add your Zig code there along with any potential instructions on how to build it.

If you want to also submit a JAI implementation and the `submissions/jai` directory does not exist yet, you just create it yourself, but you still create the necessary subdirectory with your GitHub username. 