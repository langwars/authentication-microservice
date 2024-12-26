# Which Programming Language is the Fastest?

## Introduction

This repository contains all the code that is presented in the YouTube video: ["Which Programming Language is the Fastest?"](https://www.youtube.com/watch?v=add-the-proper-link-after-it-is-posted).

## Project Structure

The project is divided into 3 main directories:
- `benchmark`: This directory contains the Apache Jmeter file that is used to run the benchmark, the results of the `llm` benchmark, and will also contain the results of the benchmarks for the user submitted code.
- `code`: This directory contains all the code that was submitted by the AI (in the `llm` directory), and will also hold the code of the fastest user submissions per language.
- `submissions`: This is where you create your own submission, through a pull request.

## Links

- [YouTube Video](https://www.youtube.com/watch?v=add-the-proper-link-after-it-is-posted)
- [GitHub Repository](https://github.com/langwars/authentication-microservice)
- [Discord Server](https://discord.gg/3bpR9tkgTQ)

## Frequently Asked Questions

Q: How do I open the AuthMicroservicePlan.jmx?

A: First you need to install [Apache Jmeter](https://jmeter.apache.org/). You can then open it through the GUI to see its structure. If you want to run the benchmark, you can do something like this: 

```bash
jmeter -n -t benchmark/AuthMicroservicePlan.jmx -l benchmark/user/results-scalan/results.csv -e -o benchmark/user/results-scalan/web
```
Please DO NOT submit pull requests with edits to the jmx file and DO NOT save your results in the benchmark directory. I will not accept any pull requests that includes modifications to any directory other than submissions.

--

Q: How do I submit my code?

A: Please check the README.md file in the submissions directory.

--

Q: How do I see the results?

A: For the LLM results, you can check the video at the top of the page for a summarized version. If you want to see an individual result, you can check the `benchmark/llm/results-<language>/web` directory. For the user submitted results, you can check the `benchmark/user/results-<language>/web` directory. If this directory does not exist for your favorite language, consider taking the challenge and submitting your code. See README.md in the submissions directory for more information.

--

Q: If I have a question, how do I ask it?

A: You have 3 main options:
1. You can ask it on the [YouTube comments](https://www.youtube.com/watch?v=add-the-proper-link-after-it-is-posted). 
2. You can create a [new issue](https://github.com/langwars/authentication-microservice/issues/new) in this repository.
3. You can join our [Discord server](https://discord.gg/3bpR9tkgTQ) and ask your question in the #general channel.

--

Q: Can I submit my code for a language that is not in the LLM list?

A: ABSO-FREAKIN-LUTELY! As long as I can run your language in my Macbook, I will accept it. I even have access to JAI. For more information check the README.md file in the submissions directory.

--

Q: What do I win if my submission is the fastest?

A: Bragging rights. In the future we might discuss some proper rewards.